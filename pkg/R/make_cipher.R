make_cipher <- function(file_prefix = make.names(tolower(Sys.getenv("COMPUTERNAME"))), host_ip , host_port, password, shared_key, export = FALSE){
#' Create \code{remoter} Authorization Objects
#'
#' \code{remoter_auth} creates an encrypted object used to securely start and connect to a \code{remoter} session (see \code{\link[remoter]{remoter-package}} for documentation)
#'
#' @param file_prefix (string) The prefix for the output file in the user directory having suffix "_remoter_auth.rdata"
#' @param host_ip (string) The IPV4 address for the server (hostnames are not allowed).
#' @param host_port (string,integer) The port to use for the server: should be a static, reserved port
#' @param password (string) The password for the server
#' @param shared_key (string) The key to encrypt and decrypt the generated cipher
#' @param export (logical | \code{FALSE}) When \code{TRUE}, the cipher will be saved to the user directory as "~/"\code{file_prefix}_\code{remoter_auth.rdata}"
#'
#' @return The cipher (invisibly) having required attributes \code{nonce}, \code{port}, and \code{addr}
#'
#' @export

  .cipher_name <- paste0(file_prefix, "_cipher");
  .file_name  <- sprintf("~/%s_remoter_auth.rdata", file_prefix);

  # password ::
  if (missing(password)){
   password <- askpass::askpass(prompt = "Enter text to use as the server password:")
  } else if (!any(class(password) |> grepl(pattern = "character"))){
   stop("The value type for `password` must be 'character': exiting ...")
  } else {
   message("Valid type for `password` detected ... ")
  }

  # shared_key
  if (missing(shared_key)){
   shared_key <- askpass::askpass(prompt = "Enter text to use as the cipher shared key:")
  } else if (!any(class(shared_key) |> grepl(pattern = "raw|character"))){
   stop("The value type for `shared_key` must be 'character' or 'raw': exiting ...")
  } else {
   message("Valid type for `shared_key` detected ... ");
   if (!is.raw(shared_key)){ shared_key <- sodium::sha256(charToRaw(shared_key)) }
  }

  .nonce <- c(Sys.getenv("COMPUTERNAME"), Sys.time()) |> paste(collapse = "::") |> charToRaw() |> magrittr::extract(1:24);
  assign(.cipher_name, {
  sodium::data_encrypt(msg = charToRaw(password), key = shared_key, nonce = .nonce) |>
   magrittr::set_attr("nonce", .nonce) |>
   magrittr::set_attr("port" , host_port) |>
   magrittr::set_attr("addr" , host_ip)
  }, envir = environment());
  if (export){
    if (file.exists(.file_name)){ file.rename(.file_name, sprintf("%s_%s.old", .file_name, format(Sys.time(), "%Y%m%d_%H%M%S"))) }
    save(file = .file_name, list = c(.cipher_name, "shared_key"), compress = "bzip2", eval.promises = TRUE, precheck = TRUE)
  }
  invisible(rlang::sym(.cipher_name) |> eval());
}
#
make_cipher_env <- function(cipher = NULL, shared_key = NULL, session = make.names(tolower(Sys.getenv("COMPUTERNAME")))){
#' Make a Cipher OS Environment Variable
#'
#' \code{make_cipher_env}() creates a Windows OS environment variable string from the provided cipher. OS environment variables beginning with 'remoter_' and ending with the target session string are searched when calling \code{\link{connect_remote}} with \code{credentials = "ENV"}.
#'
#' @param cipher If \code{NULL},the R image holding encryption objects is interactively chosen; otherwise, an object created with \code{\link{make_cipher}}.
#' @param shared_key If the shared key was not included in the cipher object, this value is checked and throws an error if empty
#' @param session The name of the session for which the environment variable string is created
#'
#' @return a JSON string that can be stored in a Windows OS environment variable formatted as "remoter_<session>"
#'
#' @export

  if (rlang::is_empty(cipher)){
    load(tcltk::tk_choose.files(multi = FALSE, caption = "Choose the cipher image to load:"), envir = environment())
    cipher <- get(ls(pattern = paste0(session, ".+cipher")));
  }

  if (class(cipher) %in% c("environment", "list")){
    .tmp_env <- as.environment(cipher);

    this <- ls(pattern = "cipher", all.names = TRUE, envir = .tmp_env)
    if (length(this) > 1) { this <- tcltk::tk_select.list(choices = this, preselect = this[1], title = "Choose a cipher object to use: ") }
    cipher <- .tmp_env[[this]];

    this <- ls(pattern = "key", all.names = TRUE, envir = .tmp_env)
    if (length(this) > 1) { this <- tcltk::tk_select.list(choices = this, preselect = this[1], title = "Choose a decryption key object to use: ") }
    shared_key <- .tmp_env[[this]]
  }

  if (rlang::is_empty(shared_key)){ stop("No shared key was found for the supplied cipher: exiting ...") }
  nonce  = attr(cipher, "nonce")
  addr   = attr(cipher, "addr")
  port   = attr(cipher, "port")

  .out = rlang::list2("remoter_{session}" := mget(ls()) |> purrr::map(paste, collapse = "") |> jsonlite::toJSON()) |> unlist()
  writeClipboard(.out)
  return(.out)
}
