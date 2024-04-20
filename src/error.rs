use askama::Template;
use poem::{http::StatusCode, Response};

#[derive(Template)]
#[template(path = "error/404.html.askama", escape = "html")]
struct NotFoundErrorPage;

#[derive(Template)]
#[template(path = "error/unauthorized.html.askama", escape = "html")]
struct UnauthorizedErrorPage;

pub(crate) fn make_not_found_response() -> Response {
    Response::builder().status(StatusCode::NOT_FOUND).body(
        NotFoundErrorPage
            .render()
            .unwrap_or_else(|_| "404 - Page not found".to_string()),
    )
}

pub(crate) fn make_unauthorized_error() -> poem::Error {
    poem::Error::from_response(
        Response::builder().status(StatusCode::UNAUTHORIZED).body(
            UnauthorizedErrorPage
                .render()
                .unwrap_or_else(|_| "Unauthorized".to_string()),
        ),
    )
}

pub(crate) fn make_internal_error() -> poem::Error {
    poem::Error::from_response(
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("Error 500. Internal Server Error"),
    )
}
