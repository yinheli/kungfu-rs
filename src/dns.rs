use std::{pin::Pin, process, sync::Arc};

use futures::Future;
use tokio::{net::UdpSocket, runtime::Runtime};
use trust_dns_proto::op::header::MessageType;
use trust_dns_server::{
    server::{Request, RequestHandler, ResponseHandler},
    ServerFuture,
};

use crate::setting::Setting;

pub async fn serve(setting: Arc<Setting>, runtime: &Runtime) {
    let handler = DnsServerHandler { setting };
    let mut server = ServerFuture::new(handler);
    let socket = match UdpSocket::bind("0.0.0.0:53").await {
        Ok(v) => v,
        Err(e) => {
            error!("listen dns server, err: {:?}", e);
            process::exit(1);
        }
    };
    server.register_socket(socket, runtime);
    debug!("dns server start");
    server.block_until_done().await.unwrap();
}

struct DnsServerHandler {
    setting: Arc<Setting>,
}

impl RequestHandler for DnsServerHandler {
    type ResponseFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

    fn handle_request<R: ResponseHandler>(
        &self,
        request: Request,
        _response_handle: R,
    ) -> Self::ResponseFuture {
        match request.message.message_type() {
            MessageType::Query => {
                println!("{:?}", request.message);
            }
            MessageType::Response => {}
        }
        // panic!("todo");
        Box::pin(async {})
    }
}
