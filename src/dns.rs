use std::{net::IpAddr, pin::Pin, sync::Arc};

use futures::Future;
use tokio::{net::UdpSocket, runtime::Runtime};
use trust_dns_client::{
    op::{Header, OpCode},
    rr::{Record, RecordType},
};
use trust_dns_proto::op::header::MessageType;
use trust_dns_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime},
    AsyncResolver, TokioAsyncResolver,
};
use trust_dns_server::{
    authority::{MessageRequest, MessageResponseBuilder},
    server::{Request, RequestHandler, ResponseHandler},
    ServerFuture,
};

use crate::setting::Setting;

pub async fn serve(setting: Arc<Setting>, runtime: Arc<Runtime>) -> Result<(), String> {
    let dns_upstream = &setting.clone().dns_upstream;
    let resolver = create_resolver(dns_upstream, runtime.clone()).await?;

    let dns_fallback = &setting.clone().dns_fallback;
    let resolver_fallback = create_resolver(dns_fallback, runtime.clone()).await?;

    let opt = DnsServerOpt {
        setting: setting.clone(),
        resolver: Arc::new(resolver),
        resolver_fallback: Arc::new(resolver_fallback),
    };

    let handler = DnsServer::new(Arc::new(opt));

    let mut server = ServerFuture::new(handler);
    let server_addr = format!("0.0.0.0:{}", setting.dns_port);
    let socket = UdpSocket::bind(server_addr)
        .await
        .map_err(|e| format!("listen dns server, err: {:?}", e))?;
    server.register_socket(socket, &runtime);
    debug!("dns server start");
    Ok(server
        .block_until_done()
        .await
        .map_err(|e| format!("{}", e))?)
}

async fn create_resolver(hosts: &Vec<String>, runtime: Arc<Runtime>) -> Result<Resolver, String> {
    let handle = runtime.handle().to_owned();
    let mut ips = vec![];
    for host in hosts {
        let ip: IpAddr = host
            .parse()
            .map_err(|e| format!("invalid dns host: {}, err: {:?}", host, e))?;
        ips.push(ip);
    }
    let name_server_group = NameServerConfigGroup::from_ips_clear(&ips, 53);
    let config = ResolverConfig::from_parts(None, vec![], name_server_group);
    let mut options = ResolverOpts::default();
    options.cache_size = 1024;
    TokioAsyncResolver::new(config, options, handle)
        .await
        .map_err(|e| format!("create resolver failed: {:?}", e))
}

type Resolver = AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>;

struct DnsServerOpt {
    setting: Arc<Setting>,
    resolver: Arc<Resolver>,
    resolver_fallback: Arc<Resolver>,
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

        let res = self
            .opt
            .clone()
            .resolver
            .clone()
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
