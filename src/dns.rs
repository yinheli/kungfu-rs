use std::{
    borrow::Borrow,
    convert::TryInto,
    iter,
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    ops::Deref,
    pin::Pin,
    process,
    slice::Iter,
    sync::Arc,
};

use futures::Future;
use tokio::{
    net::UdpSocket,
    runtime::{Handle, Runtime},
};
use trust_dns_client::{
    client::{AsyncClient, Client, SyncClient},
    op::{Header, OpCode},
    rr::{Record, RecordType},
    udp::{UdpClientConnection, UdpClientStream},
};
use trust_dns_proto::op::header::MessageType;
use trust_dns_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    error::ResolveError,
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime},
    AsyncResolver, IntoName, TokioAsyncResolver,
};
use trust_dns_server::{
    authority::{MessageRequest, MessageResponseBuilder},
    server::{Request, RequestHandler, ResponseHandler},
    ServerFuture,
};

use crate::setting::Setting;

type Resolver = AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>;

pub async fn serve(setting: Arc<Setting>, runtime: Arc<Runtime>) {
    let mut resolvers = vec![];
    for dns_host in &setting.clone().dns_upstream {
        let resolver = create_resolver(dns_host, runtime.clone()).await.unwrap();
        resolvers.push(resolver);
    }
    let mut resolver_fallbacks = vec![];
    for dns_host in &setting.clone().dns_fallback {
        let resolver = create_resolver(dns_host, runtime.clone()).await.unwrap();
        resolver_fallbacks.push(resolver);
    }

    let opt = DnsServerOpt {
        setting,
        resolvers: Arc::new(resolvers),
        resolver_fallbacks: Arc::new(resolver_fallbacks),
    };

    let handler = DnsServer::new(Arc::new(opt));
    let mut server = ServerFuture::new(handler);
    let socket = match UdpSocket::bind("0.0.0.0:53").await {
        Ok(v) => v,
        Err(e) => {
            error!("listen dns server, err: {:?}", e);
            process::exit(1);
        }
    };
    server.register_socket(socket, &runtime);
    debug!("dns server start");
    server.block_until_done().await.unwrap();
}

async fn create_resolver(host: &str, runtime: Arc<Runtime>) -> Result<Resolver, ResolveError> {
    let handle = runtime.handle().to_owned();
    let addr = host
        .parse()
        .map_err(|e| format!("invalid dns host: {}, err: {:?}", host, e))?;
    let name_server_group = NameServerConfigGroup::from_ips_clear(&[IpAddr::V4(addr)], 53);
    let config = ResolverConfig::from_parts(None, vec![], name_server_group);
    let mut options = ResolverOpts::default();
    options.cache_size = 1024;
    TokioAsyncResolver::new(config, options, handle).await
}

struct DnsServerOpt {
    setting: Arc<Setting>,
    resolvers: Arc<Vec<Resolver>>,
    resolver_fallbacks: Arc<Vec<Resolver>>,
}

struct DnsServer {
    opt: Arc<DnsServerOpt>,
}

impl DnsServer {
    fn new(opt: Arc<DnsServerOpt>) -> Self {
        DnsServer { opt }
    }
}

impl RequestHandler for DnsServer {
    type ResponseFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

    fn handle_request<R: ResponseHandler>(
        &self,
        request: Request,
        response_handle: R,
    ) -> Self::ResponseFuture {
        let handler = QueryHandler::new(self.opt.clone());

        let request_message = request.message;
        if request_message.message_type() == MessageType::Query {
            if request_message.op_code() == OpCode::Query {
                let queries = request_message.queries();
                if queries.len() > 0 {
                    let query = &queries[0];
                    if query.query_type() == RecordType::A {
                        return Box::pin(handler.query_upstream(request_message, response_handle));
                    }
                }
            }
        }
        Box::pin(handler.query_upstream(request_message, response_handle))
    }
}

struct QueryHandler {
    opt: Arc<DnsServerOpt>,
}

impl QueryHandler {
    fn new(opt: Arc<DnsServerOpt>) -> Self {
        QueryHandler { opt }
    }
}

impl QueryHandler {
    async fn query_upstream<R: ResponseHandler>(self, request: MessageRequest, response_handle: R) {
        let queries = request.queries();
        let query = &queries[0];
        let record_type = query.query_type();
        let name = query.name();

        let res = self.opt.clone().resolvers.clone()[0]
            .lookup(name, record_type, Default::default())
            .await
            .unwrap();

        println!("res: {:?}", res);

        let mut answers = vec![];
        let _name_servers: Vec<&Record> = vec![];
        let _soa: Vec<&Record> = vec![];
        let _additionals: Vec<&Record> = vec![];
        for x in res.record_iter() {
            match x.record_type() {
                RecordType::A => answers.push(x),
                _ => {}
            }
        }

        let mut header = Header::new();
        header.set_id(request.id());
        header.set_op_code(request.op_code());
        header.set_message_type(MessageType::Response);

        let builder = MessageResponseBuilder::new(Some(request.raw_queries()));

        let a = res.record_iter();
        let mut list = vec![];
        for x in a {
            list.push(x);
        }

        let answers = Box::new(answers.into_iter()) as Box<dyn Iterator<Item = &Record> + Send>;
        let name_servers = Box::new([].iter()) as Box<dyn Iterator<Item = &Record> + Send>;
        let soa = Box::new([].iter()) as Box<dyn Iterator<Item = &Record> + Send>;
        let additionals = Box::new([].iter()) as Box<dyn Iterator<Item = &Record> + Send>;
        let response = builder.build(header, answers, name_servers, soa, additionals);
        let _ = response_handle.send_response(response);
    }
}
