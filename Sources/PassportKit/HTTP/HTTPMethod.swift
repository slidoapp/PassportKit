/// An HTTP request method.
public enum HTTPMethod: String, Sendable, Hashable {
    /// `GET`
    case get = "GET"
    /// `POST`
    case post = "POST"
    /// `PUT`
    case put = "PUT"
    /// `PATCH`
    case patch = "PATCH"
    /// `DELETE`
    case delete = "DELETE"
    /// `HEAD`
    case head = "HEAD"
}
