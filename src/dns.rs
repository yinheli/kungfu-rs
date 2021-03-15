use std::{
    borrow::Borrow,
    convert::TryInto,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs},
    ops::Deref,
    pin::Pin,
    process,
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
use trust_dns_proto::{op::header::MessageType, xfer::DnsRequestOptions};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    IntoName, TokioAsyncResolver,
};
use trust_dns_server::{
    authority::{
        AuthLookup, LookupObject, MessageRequest, MessageResponse, MessageResponseBuilder,
    },
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
    let rt = runtime.clone();
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
        // println!("query_upstream: {:?}", self.setting);

        println!("request: {:#?}", request);

        // let queries = request.queries();
        // let query = &queries[0];

        // let address = "1.2.4.8:53".parse().unwrap();
        // let conn = UdpClientConnection::new(address).unwrap();
        // let client = SyncClient::new(conn);
        // let name = query.name().into_name().unwrap();
        // let result = client
        //     .query(&name, query.query_class(), query.query_type())
        //     .unwrap();
        // let answers = result.answers().into_iter().collect::<Vec<Record>>();
        // let additionals =
        //     Box::new(result.additionals().into_iter().to_owned()) as Box<dyn Iterator<Item = _>>;
        // let nameservers =
        //     Box::new(result.name_servers().into_iter().to_owned()) as Box<dyn Iterator<Item = _>>;

        // let mut header = Header::new();
        // header.set_id(request.id());
        // header.set_op_code(request.op_code());
        // header.set_message_type(MessageType::Response);
        // let response_builder = MessageResponseBuilder::new(Some(request.raw_queries()));
        // let response = response_builder.build(header, answers, nameservers, answers, additionals);
        // let _ = response_handle.send_response(response);
    }

    // fn fun_name(self, request: MessageRequest, response_handle: R) {
    //     let handle = self.runtime.handle().clone();
    //     let resolver =
    //         TokioAsyncResolver::new(ResolverConfig::google(), ResolverOpts::default(), handle)
    //             .await
    //             .unwrap();
    //     let queries = request.queries();
    //     let query = &queries[0];
    //     let mut lookup_opt = DnsRequestOptions::default();
    //     lookup_opt.expects_multiple_responses = true;
    //     let vv = resolver.ns_lookup(query.name()).await.unwrap();
    //     let f = resolver.lookup(query.name(), query.query_type(), lookup_opt);
    //     let lookup = f.await.unwrap();
    //     let response_builder = MessageResponseBuilder::new(Some(request.raw_queries()));
    //     let mut header = Header::new();
    //     header.set_id(request.id());
    //     header.set_op_code(request.op_code());
    //     header.set_message_type(MessageType::Response);
    //     let a = Box::new(AuthLookup::default()) as Box<dyn LookupObject>;
    //     let b = Box::new(AuthLookup::default()) as Box<dyn LookupObject>;
    //     let c = Box::new(AuthLookup::default()) as Box<dyn LookupObject>;
    //     let d = Box::new(AuthLookup::default()) as Box<dyn LookupObject>;
    //     println!("lookup: {:#?}", lookup);
    //     for v in lookup.into_iter() {
    //         let a = v.to_record_type();
    //         println!("--> {:?}", a);
    //         println!("{:?}", v);
    //     }
    //     let response = response_builder.build(header, a.iter(), b.iter(), c.iter(), d.iter());
    //     let _ = response_handle.send_response(response);
    // }
}
