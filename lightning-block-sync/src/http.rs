use chunked_transfer;
use serde_json;

use std::convert::TryFrom;
#[cfg(not(feature = "tokio"))]
use std::io::Write;
use std::net::ToSocketAddrs;
use std::time::Duration;

#[cfg(feature = "tokio")]
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tokio")]
use tokio::net::TcpStream;

#[cfg(not(feature = "tokio"))]
use std::io::BufRead;
use std::io::Read;
#[cfg(not(feature = "tokio"))]
use std::net::TcpStream;

/// Maximum HTTP message header size in bytes.
const MAX_HTTP_MESSAGE_HEADER_SIZE: usize = 8192;

/// Maximum HTTP message body size in bytes. Enough for a hex-encoded block in JSON format.
const MAX_HTTP_MESSAGE_BODY_SIZE: usize = 2 * 4_000_000 + 64;

/// Endpoint for interacting with an HTTP-based API.
#[derive(Debug)]
pub struct HttpEndpoint {
	scheme: Scheme,
	host: String,
	port: Option<u16>,
	path: String,
}

/// URI scheme compatible with an HTTP endpoint.
#[derive(Debug)]
pub enum Scheme {
	HTTP,
	HTTPS,
}

impl HttpEndpoint {
	/// Creates an endpoint using the HTTP scheme.
	pub fn insecure_host(host: String) -> Self {
		Self {
			scheme: Scheme::HTTP,
			host,
			port: None,
			path: String::from("/"),
		}
	}

	/// Creates an endpoint using the HTTPS scheme.
	pub fn secure_host(host: String) -> Self {
		Self {
			scheme: Scheme::HTTPS,
			host,
			port: None,
			path: String::from("/"),
		}
	}

	/// Specifies a port to use with the endpoint.
	pub fn with_port(mut self, port: u16) -> Self {
		self.port = Some(port);
		self
	}

	/// Specifies a path to use with the endpoint.
	pub fn with_path(mut self, path: String) -> Self {
		self.path = path;
		self
	}

	/// Returns the endpoint host.
	pub fn host(&self) -> &str {
		&self.host
	}

	/// Returns the endpoint port.
	pub fn port(&self) -> u16 {
		match self.port {
			None => match self.scheme {
				Scheme::HTTP => 80,
				Scheme::HTTPS => 443,
			},
			Some(port) => port,
		}
	}

	/// Returns the endpoint path.
	pub fn path(&self) -> &str {
		&self.path
	}
}

impl<'a> std::net::ToSocketAddrs for &'a HttpEndpoint {
	type Iter = <(&'a str, u16) as std::net::ToSocketAddrs>::Iter;

	fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
		(self.host(), self.port()).to_socket_addrs()
	}
}

/// Client for making HTTP requests.
pub(crate) struct HttpClient {
	stream: TcpStream,
}

impl HttpClient {
	/// Opens a connection to an HTTP endpoint.
	pub fn connect<E: ToSocketAddrs>(endpoint: E) -> std::io::Result<Self> {
		let address = match endpoint.to_socket_addrs()?.next() {
			None => {
				return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "could not resolve to any addresses"));
			},
			Some(address) => address,
		};
		let stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1))?;
		stream.set_read_timeout(Some(Duration::from_secs(2)))?;
		stream.set_write_timeout(Some(Duration::from_secs(1)))?;

		#[cfg(feature = "tokio")]
		let stream = {
			stream.set_nonblocking(true)?;
			TcpStream::from_std(stream)?
		};

		Ok(Self { stream })
	}

	/// Sends a `GET` request for a resource identified by `uri` at the `host`.
	///
	/// Returns the response body in `F` format.
	pub async fn get<F>(&mut self, uri: &str, host: &str) -> std::io::Result<F>
	where F: TryFrom<Vec<u8>, Error = std::io::Error> {
		let request = format!(
			"GET {} HTTP/1.1\r\n\
			 Host: {}\r\n\
			 Connection: keep-alive\r\n\
			 \r\n", uri, host);
		let response_body = self.send_request_with_retry(&request).await?;
		F::try_from(response_body)
	}

	/// Sends a `POST` request for a resource identified by `uri` at the `host` using the given HTTP
	/// authentication credentials.
	///
	/// The request body consists of the provided JSON `content`. Returns the response body in `F`
	/// format.
	pub async fn post<F>(&mut self, uri: &str, host: &str, auth: &str, content: serde_json::Value) -> std::io::Result<F>
	where F: TryFrom<Vec<u8>, Error = std::io::Error> {
		let content = content.to_string();
		let request = format!(
			"POST {} HTTP/1.1\r\n\
			 Host: {}\r\n\
			 Authorization: {}\r\n\
			 Connection: keep-alive\r\n\
			 Content-Type: application/json\r\n\
			 Content-Length: {}\r\n\
			 \r\n\
			 {}", uri, host, auth, content.len(), content);
		let response_body = self.send_request_with_retry(&request).await?;
		F::try_from(response_body)
	}

	/// Sends an HTTP request message and reads the response, returning its body. Attempts to
	/// reconnect and retry if the connection has been closed.
	async fn send_request_with_retry(&mut self, request: &str) -> std::io::Result<Vec<u8>> {
		let endpoint = self.stream.peer_addr().unwrap();
		match self.send_request(request).await {
			Ok(bytes) => Ok(bytes),
			Err(e) => match e.kind() {
				std::io::ErrorKind::ConnectionReset |
				std::io::ErrorKind::ConnectionAborted |
				std::io::ErrorKind::UnexpectedEof => {
					// Reconnect if the connection was closed.
					*self = Self::connect(endpoint)?;
					self.send_request(request).await
				},
				_ => Err(e),
			},
		}
	}

	/// Sends an HTTP request message and reads the response, returning its body.
	async fn send_request(&mut self, request: &str) -> std::io::Result<Vec<u8>> {
		self.write_request(request).await?;
		self.read_response().await
	}

	/// Writes an HTTP request message.
	async fn write_request(&mut self, request: &str) -> std::io::Result<()> {
		#[cfg(feature = "tokio")]
		{
			self.stream.write_all(request.as_bytes()).await?;
			self.stream.flush().await
		}
		#[cfg(not(feature = "tokio"))]
		{
			self.stream.write_all(request.as_bytes())?;
			self.stream.flush()
		}
	}

	/// Reads an HTTP response message.
	async fn read_response(&mut self) -> std::io::Result<Vec<u8>> {
		#[cfg(feature = "tokio")]
		let stream = self.stream.split().0;
		#[cfg(not(feature = "tokio"))]
		let stream = std::io::Read::by_ref(&mut self.stream);

		let limited_stream = stream.take(MAX_HTTP_MESSAGE_HEADER_SIZE as u64);

		#[cfg(feature = "tokio")]
		let mut reader = tokio::io::BufReader::new(limited_stream);
		#[cfg(not(feature = "tokio"))]
		let mut reader = std::io::BufReader::new(limited_stream);

		macro_rules! read_line { () => { {
			let mut line = String::new();
			#[cfg(feature = "tokio")]
			let bytes_read = reader.read_line(&mut line).await?;
			#[cfg(not(feature = "tokio"))]
			let bytes_read = reader.read_line(&mut line)?;

			match bytes_read {
				0 => None,
				_ => {
					// Remove trailing CRLF
					if line.ends_with('\n') { line.pop(); if line.ends_with('\r') { line.pop(); } }
					Some(line)
				},
			}
		} } }

		// Read and parse status line
		let status_line = read_line!()
			.ok_or(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no status line"))?;
		let status = HttpStatus::parse(&status_line)?;

		// Read and parse relevant headers
		let mut message_length = HttpMessageLength::Empty;
		loop {
			let line = read_line!()
				.ok_or(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no headers"))?;
			if line.is_empty() { break; }

			let header = HttpHeader::parse(&line)?;
			if header.has_name("Content-Length") {
				let length = header.value.parse()
					.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
				if let HttpMessageLength::Empty = message_length {
					message_length = HttpMessageLength::ContentLength(length);
				}
				continue;
			}

			if header.has_name("Transfer-Encoding") {
				message_length = HttpMessageLength::TransferEncoding(header.value.into());
				continue;
			}
		}

		if !status.is_ok() {
			return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found"));
		}

		// Read message body
		let read_limit = MAX_HTTP_MESSAGE_BODY_SIZE - reader.buffer().len();
		reader.get_mut().set_limit(read_limit as u64);
		match message_length {
			HttpMessageLength::Empty => { Ok(Vec::new()) },
			HttpMessageLength::ContentLength(length) => {
				if length == 0 || length > MAX_HTTP_MESSAGE_BODY_SIZE {
					Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "out of range"))
				} else {
					let mut content = vec![0; length];
					#[cfg(feature = "tokio")]
					reader.read_exact(&mut content[..]).await?;
					#[cfg(not(feature = "tokio"))]
					reader.read_exact(&mut content[..])?;
					Ok(content)
				}
			},
			HttpMessageLength::TransferEncoding(coding) => {
				if !coding.eq_ignore_ascii_case("chunked") {
					Err(std::io::Error::new(
							std::io::ErrorKind::InvalidInput, "unsupported transfer coding"))
				} else {
					#[cfg(feature = "tokio")]
					let reader = ReadAdapter(&mut reader);
					let mut decoder = chunked_transfer::Decoder::new(reader);
					let mut content = Vec::new();
					decoder.read_to_end(&mut content)?;
					Ok(content)
				}
			},
		}
	}
}

/// HTTP response status code as defined by [RFC 7231].
///
/// [RFC 7231]: https://tools.ietf.org/html/rfc7231#section-6
struct HttpStatus<'a> {
	code: &'a str,
}

impl<'a> HttpStatus<'a> {
	/// Parses an HTTP status line as defined by [RFC 7230].
	///
	/// [RFC 7230]: https://tools.ietf.org/html/rfc7230#section-3.1.2
	fn parse(line: &'a String) -> std::io::Result<HttpStatus<'a>> {
		let mut tokens = line.splitn(3, ' ');

		let http_version = tokens.next()
			.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "no HTTP-Version"))?;
		if !http_version.eq_ignore_ascii_case("HTTP/1.1") &&
			!http_version.eq_ignore_ascii_case("HTTP/1.0") {
			return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid HTTP-Version"));
		}

		let code = tokens.next()
			.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "no Status-Code"))?;
		if code.len() != 3 || !code.chars().all(|c| c.is_ascii_digit()) {
			return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid Status-Code"));
		}

		let _reason = tokens.next()
			.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "no Reason-Phrase"))?;

		Ok(Self { code })
	}

	/// Returns whether the status is successful (i.e., 2xx status class).
	fn is_ok(&self) -> bool {
		self.code.starts_with('2')
	}
}

/// HTTP response header as defined by [RFC 7231].
///
/// [RFC 7231]: https://tools.ietf.org/html/rfc7231#section-7
struct HttpHeader<'a> {
	name: &'a str,
	value: &'a str,
}

impl<'a> HttpHeader<'a> {
	/// Parses an HTTP header field as defined by [RFC 7230].
	///
	/// [RFC 7230]: https://tools.ietf.org/html/rfc7230#section-3.2
	fn parse(line: &'a String) -> std::io::Result<HttpHeader<'a>> {
		let mut tokens = line.splitn(2, ':');
		let name = tokens.next()
			.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "no header name"))?;
		let value = tokens.next()
			.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "no header value"))?
			.trim_start();
		Ok(Self { name, value })
	}

	/// Returns whether the header field has the given name.
	fn has_name(&self, name: &str) -> bool {
		self.name.eq_ignore_ascii_case(name)
	}
}

/// HTTP message body length as defined by [RFC 7230].
///
/// [RFC 7230]: https://tools.ietf.org/html/rfc7230#section-3.3.3
enum HttpMessageLength {
	Empty,
	ContentLength(usize),
	TransferEncoding(String),
}

/// An adaptor for making `tokio::io::AsyncRead` compatible with interfaces expecting
/// `std::io::Read`. This effectively makes the adapted object synchronous.
#[cfg(feature = "tokio")]
struct ReadAdapter<'a, R: tokio::io::AsyncRead + std::marker::Unpin>(&'a mut R);

#[cfg(feature = "tokio")]
impl<'a, R: tokio::io::AsyncRead + std::marker::Unpin> std::io::Read for ReadAdapter<'a, R> {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		futures::executor::block_on(self.0.read(buf))
	}
}

/// An HTTP response body in binary format.
pub(crate) struct BinaryResponse(pub(crate) Vec<u8>);

/// An HTTP response body in JSON format.
pub(crate) struct JsonResponse(pub(crate) serde_json::Value);

/// Interprets bytes from an HTTP response body as binary data.
impl TryFrom<Vec<u8>> for BinaryResponse {
	type Error = std::io::Error;

	fn try_from(bytes: Vec<u8>) -> std::io::Result<Self> {
		Ok(BinaryResponse(bytes))
	}
}

/// Interprets bytes from an HTTP response body as a JSON value.
impl TryFrom<Vec<u8>> for JsonResponse {
	type Error = std::io::Error;

	fn try_from(bytes: Vec<u8>) -> std::io::Result<Self> {
		Ok(JsonResponse(serde_json::from_slice(&bytes)?))
	}
}

#[cfg(test)]
mod endpoint_tests {
	use super::HttpEndpoint;

	#[test]
	fn to_insecure_host() {
		let endpoint = HttpEndpoint::insecure_host("foo.com".into());
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.port(), 80);
	}

	#[test]
	fn to_secure_host() {
		let endpoint = HttpEndpoint::secure_host("foo.com".into());
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.port(), 443);
	}

	#[test]
	fn with_custom_port() {
		let endpoint = HttpEndpoint::insecure_host("foo.com".into()).with_port(8080);
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.port(), 8080);
	}

	#[test]
	fn with_uri_path() {
		let endpoint = HttpEndpoint::insecure_host("foo.com".into()).with_path("/path".into());
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.path(), "/path");
	}

	#[test]
	fn without_uri_path() {
		let endpoint = HttpEndpoint::insecure_host("foo.com".into());
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.path(), "/");
	}

	#[test]
	fn convert_to_socket_addrs() {
		let endpoint = HttpEndpoint::insecure_host("foo.com".into());
		let host = endpoint.host();
		let port = endpoint.port();

		use std::net::ToSocketAddrs;
		match (&endpoint).to_socket_addrs() {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(mut socket_addrs) => {
				match socket_addrs.next() {
					None => panic!("Expected socket address"),
					Some(addr) => {
						assert_eq!(addr, (host, port).to_socket_addrs().unwrap().next().unwrap());
						assert!(socket_addrs.next().is_none());
					}
				}
			}
		}
	}
}

#[cfg(test)]
pub(crate) mod client_tests {
	use super::*;
	use std::io::BufRead;
	use std::io::Write;

	/// Server for handling HTTP client requests with a stock response.
	pub struct HttpServer {
		address: std::net::SocketAddr,
		handler: std::thread::JoinHandle<()>,
		shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
	}

	/// Body of HTTP response messages.
	pub enum MessageBody<T: ToString> {
		Empty,
		Content(T),
		ChunkedContent(T),
	}

	impl HttpServer {
		pub fn responding_with_ok<T: ToString>(body: MessageBody<T>) -> Self {
			let response = match body {
				MessageBody::Empty => "HTTP/1.1 200 OK\r\n\r\n".to_string(),
				MessageBody::Content(body) => {
					let body = body.to_string();
					format!(
						"HTTP/1.1 200 OK\r\n\
						 Content-Length: {}\r\n\
						 \r\n\
						 {}", body.len(), body)
				},
				MessageBody::ChunkedContent(body) => {
					let mut chuncked_body = Vec::new();
					{
						use chunked_transfer::Encoder;
						let mut encoder = Encoder::with_chunks_size(&mut chuncked_body, 8);
						encoder.write_all(body.to_string().as_bytes()).unwrap();
					}
					format!(
						"HTTP/1.1 200 OK\r\n\
						 Transfer-Encoding: chunked\r\n\
						 \r\n\
						 {}", String::from_utf8(chuncked_body).unwrap())
				},
			};
			HttpServer::responding_with(response)
		}

		pub fn responding_with_not_found() -> Self {
			let response = "HTTP/1.1 404 Not Found\r\n\r\n".to_string();
			HttpServer::responding_with(response)
		}

		fn responding_with(response: String) -> Self {
			let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
			let address = listener.local_addr().unwrap();

			let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
			let shutdown_signaled = std::sync::Arc::clone(&shutdown);
			let handler = std::thread::spawn(move || {
				for stream in listener.incoming() {
					let mut stream = stream.unwrap();
					stream.set_write_timeout(Some(Duration::from_secs(1))).unwrap();

					let lines_read = std::io::BufReader::new(&stream)
						.lines()
						.take_while(|line| !line.as_ref().unwrap().is_empty())
						.count();
					if lines_read == 0 { continue; }

					for chunk in response.as_bytes().chunks(16) {
						if shutdown_signaled.load(std::sync::atomic::Ordering::SeqCst) {
							return;
						} else {
							stream.write(chunk).unwrap();
							stream.flush().unwrap();
						}
					}
				}
			});

			Self { address, handler, shutdown }
		}

		fn shutdown(self) {
			self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
			self.handler.join().unwrap();
		}

		pub fn endpoint(&self) -> HttpEndpoint {
			HttpEndpoint::insecure_host(self.address.ip().to_string())
				.with_port(self.address.port())
		}
	}

	#[test]
	fn connect_to_unresolvable_host() {
		match HttpClient::connect(("example.invalid", 80)) {
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::Other),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn connect_with_no_socket_address() {
		match HttpClient::connect(&vec![][..]) {
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn connect_with_unknown_server() {
		match HttpClient::connect(("::", 80)) {
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionRefused),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn connect_with_valid_endpoint() {
		let server = HttpServer::responding_with_ok::<String>(MessageBody::Empty);

		match HttpClient::connect(&server.endpoint()) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(_) => {},
		}
	}

	#[tokio::test]
	async fn read_empty_message() {
		let server = HttpServer::responding_with("".to_string());

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		drop(server);
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
				assert_eq!(e.get_ref().unwrap().to_string(), "no status line");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn read_incomplete_message() {
		let server = HttpServer::responding_with("HTTP/1.1 200 OK".to_string());

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		drop(server);
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
				assert_eq!(e.get_ref().unwrap().to_string(), "no headers");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn read_too_large_message_headers() {
		let response = format!(
			"HTTP/1.1 302 Found\r\n\
			 Location: {}\r\n\
			 \r\n", "Z".repeat(MAX_HTTP_MESSAGE_HEADER_SIZE));
		let server = HttpServer::responding_with(response);

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
				assert_eq!(e.get_ref().unwrap().to_string(), "no headers");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn read_too_large_message_body() {
		let body = "Z".repeat(MAX_HTTP_MESSAGE_BODY_SIZE + 1);
		let server = HttpServer::responding_with_ok::<String>(MessageBody::Content(body));

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "out of range");
			},
			Ok(_) => panic!("Expected error"),
		}
		server.shutdown();
	}

	#[tokio::test]
	async fn read_message_with_unsupported_transfer_coding() {
		let response = String::from(
			"HTTP/1.1 200 OK\r\n\
			 Transfer-Encoding: gzip\r\n\
			 \r\n\
			 foobar");
		let server = HttpServer::responding_with(response);

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
				assert_eq!(e.get_ref().unwrap().to_string(), "unsupported transfer coding");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn read_empty_message_body() {
		let server = HttpServer::responding_with_ok::<String>(MessageBody::Empty);

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(bytes) => assert_eq!(bytes.0, Vec::<u8>::new()),
		}
	}

	#[tokio::test]
	async fn read_message_body_with_length() {
		let body = "foo bar baz qux".repeat(32);
		let content = MessageBody::Content(body.clone());
		let server = HttpServer::responding_with_ok::<String>(content);

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(bytes) => assert_eq!(bytes.0, body.as_bytes()),
		}
	}

	#[tokio::test]
	async fn read_chunked_message_body() {
		let body = "foo bar baz qux".repeat(32);
		let chunked_content = MessageBody::ChunkedContent(body.clone());
		let server = HttpServer::responding_with_ok::<String>(chunked_content);

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(bytes) => assert_eq!(bytes.0, body.as_bytes()),
		}
	}

	#[tokio::test]
	async fn reconnect_closed_connection() {
		let server = HttpServer::responding_with_ok::<String>(MessageBody::Empty);

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		assert!(client.get::<BinaryResponse>("/foo", "foo.com").await.is_ok());
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(bytes) => assert_eq!(bytes.0, Vec::<u8>::new()),
		}
	}

	#[test]
	fn from_bytes_into_binary_response() {
		let bytes = b"foo";
		match BinaryResponse::try_from(bytes.to_vec()) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(response) => assert_eq!(&response.0, bytes),
		}
	}

	#[test]
	fn from_invalid_bytes_into_json_response() {
		let json = serde_json::json!({ "result": 42 });
		match JsonResponse::try_from(json.to_string().as_bytes()[..5].to_vec()) {
			Err(_) => {},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn from_valid_bytes_into_json_response() {
		let json = serde_json::json!({ "result": 42 });
		match JsonResponse::try_from(json.to_string().as_bytes().to_vec()) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(response) => assert_eq!(response.0, json),
		}
	}
}
