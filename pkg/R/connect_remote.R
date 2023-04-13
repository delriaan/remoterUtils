connect_remote <- function(credentials = NULL, prompt = "REMOTE_SESSION::", port = NULL, action = "client", session = make.names(tolower(Sys.getenv("COMPUTERNAME"))), ...){
#' A \code{remoter} Wrapper
#'
#' \code{connect_remote} is a wrapper for \code{remoter::\link[remoter]{client}} making use of predefined encrypted authentication objects
#'
#' @details
#' When \code{credentials} is passed \emph{'ENV'}, a Windows environment variable named 'remoter_<cipher prefix>' must already be set.
#' The content of the variable should be a JSON string created with \code{\link{make_cipher_env}}.  Expected keys are as follows:
#' \itemize{
#' \item{addr: string (IPV4 format)}
#' \item{port: numeric,string}
#' \item{session: string}
#' \item{cipher: string (hexidecimal)}
#' \item{nonce: string (hexidecimal, must evaluate to length 24L raw vector)}
#' \item{shared_key: string (hexidecimal)}
#' }
#'
#' @param credentials One of the following:
#' \itemize{
#' \item{\code{string}: The path to the R workspace image containing the cipher and key needed to connect to the remote resource}
#' \item{\code{TRUE}: Choose the R workspace image interactively via \code{\link[tcltk]{tk_choose.files}}}
#' \item{'ENV': See 'Details'}
#' \item{\code{NULL|FALSE}: Use when no credentials are needed (connections will \emph{not} be secure)}
#' }
#' @param prompt (string) The prompt to use during the remote session
#' @param port (integer) The port to use if not provided in the cipher (useful for specific overrides or ad-hoc sessions)
#' @param action (string, symbol) The function to use to connect to the remote session (e.g., \code{client}, \code{batch}, etc.)
#' @param session (string) The session prefix for the ciphers when \code{credentials} is \emph{'ENV'}
#' @param ... Not used
#'
#' @section References:
#' At a minimum, read the following documentation:
#' \itemize{
#' \item{\code{\link[remoter]{client}}}
#' \item{\code{\link[remoter]{c2s}}}
#' \item{\code{\link[remoter]{s2c}}}
#' \item{\code{\link[remoter]{exit}}}
#' }
#'
#' @export

  force(prompt)
  if (!stringi::stri_detect_regex(prompt, "[:]{2}$")){ prompt <- paste0(prompt, "::") }

  action <- rlang::enexpr(action) |> as.character();

  # Create a logical selection vector ----
  .logivec <- c(`TRUE` = identical(TRUE, credentials)
                , OS_ENV	= identical("ENV", credentials)
                , OBJ 		= class(credentials) %in% c("list", "environment")
                , default = rlang::is_empty(credentials) || TRUE
                ) |> which() |> min();

  # Set the local environment ----
  eval(rlang::exprs(
    `TRUE` = {
        tcltk::tk_choose.files(multi = FALSE, caption = "Select the workspace image file containing the cipher and key:") |> load();

        this <- ls(pattern = "cipher", all.names = TRUE);

        if (length(this) > 1){ this <- tcltk::tk_select.list(choices = this, preselect = this[1], title = "Choose a cipher object to use: ")}
        cipher <- rlang::sym(this) |> eval();
        this <- ls(pattern = "key", all.names = TRUE);

        if (length(this) > 1) { this <- tcltk::tk_select.list(choices = this, preselect = this[1], title = "Choose a decryption key object to use: ")}
        shared_key <- get(this);
    }
    , OS_ENV = {
        os_env_var <- purrr::as_mapper(~.x[grepl("remoter", names(.x))] |> purrr::map(jsonlite::fromJSON))(Sys.getenv());
        attr(os_env_var, "names") <- names(os_env_var) |>
            stringi::stri_replace_first_fixed(pattern = "remoter_", replacement = "", vectorize_all = FALSE);

        shared_key <- as.raw(sodium::hex2bin(os_env_var[[session]]$shared_key));;
        cipher <- as.raw(sodium::hex2bin(os_env_var[[session]]$cipher));

        attr(cipher, "nonce") <- as.raw(sodium::hex2bin(os_env_var[[session]]$nonce));
        attr(cipher, "addr") <- os_env_var[[session]]$addr;
        attr(cipher, "port") <- os_env_var[[session]]$port;
      }
    , OBJ = {
        this <- ls(pattern = "cipher", all.names = TRUE, envir = as.environment(credentials))
        if (length(this) > 1) { this <- tcltk::tk_select.list(choices = this, preselect = this[1], title = "Choose a cipher object to use: ") }
        cipher <- (as.environment(credentials))[[this]]

        this <- ls(pattern = "key", all.names = TRUE, envir = as.environment(credentials))
        if (length(this) > 1) { this <- tcltk::tk_select.list(choices = this, preselect = this[1], title = "Choose a decryption key object to use: ") }
        shared_key <- (as.environment(credentials))[[this]]
      }
    , default = {
        message("No valid values for argument 'credentials': exiting ...")
        return()
      })[[.logivec]]);

  # Validate the address ----
  if (rlang::is_empty(hostname2addr(addr = attr(cipher, "addr")))){ stop(glue::glue("Invalid hostname: {attr(cipher, 'addr')}")) }

  # Connect ----
  .fun <- parse(text = glue::glue("remoter::{action}")) |> eval()
  .args <- { list(
      addr = attr(cipher, "addr")
      , port = attr(cipher, "port") |> as.integer()
      , password = rawToChar(sodium::data_decrypt(cipher, shared_key))
      , prompt = prompt
      )}
  do.call(.fun, .args[intersect(names(formals(.fun)), names(.args))])
}
