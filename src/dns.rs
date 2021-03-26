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
use tokio::{net::UdpSocket, runtime::Runtime};
use trust_dns_client::{
    client::{AsyncClient, Client, SyncClient},
    op::{Header, OpCode},
    rr::{Record, RecordType},
    udp::{UdpClientConnection, UdpClientStream},
};
use trust_dns_proto::op::header::MessageType;
use trust_dns_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    IntoName, TokioAsyncResolver,
};
use trust_dns_server::{
    authority::{MessageRequest, MessageResponseBuilder},
    server::{Request, RequestHandler, ResponseHandler},
    ServerFuture,
};

use crate::setting::Setting;

pub async fn serve(setting: Arc<Setting>, runtime: Arc<Runtime>) {
    let handler = DnsServer {
        setting,
        runtime: runtime.clone(),
    };
    let mut server = ServerFuture::new(handler);
    let socket = match UdpSocket::bind("0.0.0.0:53").await {
        Ok(v) => v,
        Err(e) => {
            error!("listen dns server, err: {:?}", e);
            process::exit(1);
        }
    };
    let _rt = runtime.clone();
    server.register_socket(socket, &runtime);
    debug!("dns server start");
    server.block_until_done().await.unwrap();
}

struct DnsServer {
    setting: Arc<Setting>,
    runtime: Arc<Runtime>,
}

impl RequestHandler for DnsServer {
    type ResponseFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

    fn handle_request<R: ResponseHandler>(
        &self,
        request: Request,
        response_handle: R,
    ) -> Self::ResponseFuture {
        let request_message = request.message;
        if request_message.message_type() == MessageType::Query {
            if request_message.op_code() == OpCode::Query {
                let queries = request_message.queries();
                if queries.len() > 0 {
                    let query = &queries[0];
                    if query.query_type() == RecordType::A {
                        let handler = QueryHandler {
                            setting: self.setting.clone(),
                            runtime: self.runtime.clone(),
                        };
                        return Box::pin(handler.query_upstream(request_message, response_handle));
                    }
                }
            }
        }
        let handler = QueryHandler {
            setting: self.setting.clone(),
            runtime: self.runtime.clone(),
        };
        Box::pin(handler.query_upstream(request_message, response_handle))
    }
}

struct QueryHandler {
    setting: Arc<Setting>,
    runtime: Arc<Runtime>,
}

impl QueryHandler {
    async fn query_upstream<R: ResponseHandler>(self, request: MessageRequest, response_handle: R) {
        let name_server_group =
            NameServerConfigGroup::from_ips_clear(&[IpAddr::V4(Ipv4Addr::new(1, 2, 4, 8))], 53);
        // let options = config.options.unwrap_or_default();
        let config = ResolverConfig::from_parts(None, vec![], name_server_group);

        let runtime = self.runtime.clone().handle().to_owned();
        let resolver = TokioAsyncResolver::new(config, Default::default(), runtime)
            .await
            .unwrap();

        let queries = request.queries();
        let query = &queries[0];
        let record_type = query.query_type();
        let name = query.name();

        let res = resolver
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

#[cfg(test)]
mod test {
    #[test]
    fn test_1() {
        // let a: dyn IntoIterator<Item = Option> = Box::new(None).into_iter();
        // let b: dyn IntoIterator<Item = Option, IntoIter = > = Box::new(None.into_iter());
        // assert_eq!(a, b);

        // let v = vec![Box::new(1)];
        // let a = v.iter();
        // for x in a {
        //     println!("x:{}", x)
        // }

        // let b = v.into_iter();

        // for x in b {
        //     println!("x:{}", x)
        // }
    }
}
