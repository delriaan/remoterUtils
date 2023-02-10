# ::::: Global Objects :::::
#' @importFrom rlang %<~%
#
gen_pass %<~% function(glyphs = c(letters, LETTERS, 1:100, "@", "#", "$", "=", "*"), length = NULL){
#' Generate a Password
#'
#' @param glyphs Numerals, characters to use in the password
#' @param length (int) The length of the password before converting to a raw vector
#'
#' @return A raw vector encoding of the randomly-generated password
#' @export

	set.seed(Sys.time());
  force(glyphs)
  glyphs <- as.character(rlang::enexpr(glyphs));

  sample(x = glyphs, size = ifelse(rlang::is_empty(length), length(glyphs), length), prob = runif(n = length(glyphs), min = 0.1, 0.5)) |>
  paste(collapse = "") |>
  charToRaw()
}
#
make_cipher %<~% function(file_prefix, host_ip , host_port, username, password, shared_key, export = FALSE){
#' Create \code{remoter} Authorization Objects
#'
#' \code{remoter_auth} creates an encrypted object used to securely start and connect to a \code{\link[remoter]{remoter}} session
#'
#' @param file_prefix (string) The prefix for the output file in the user directory having suffix "_remoter_auth.rdata"
#' @param host_ip (string) The IPV4 address for the server (hostnames are not allowed)
#' @param host_port (string,integer) The port to use for the server: should be a static, reserved port
#' @param username (string)
#' @param password (string) The password for the server
#' @param shared_key (string) The key to encrypt and decrypt the generated cipher
#' @param export (logical | \code{FALSE}) When \code{TRUE}, the cipher will be saved to the user directory as "~/"\code{file_prefix}_\code{remoter_auth.rdata}"
#'
#' @return The cipher (invisibly) having required attributes \code{nonce}, \code{port}, and \code{addr}
#'
#' @export

  # file_prefix
  if (missing(file_prefix)){ file_prefix <- Sys.getenv("COMPUTERNAME") |> tolower() |> make.names() }
  .cipher_name <- paste0(file_prefix, "_cipher");
  .file_name  <- sprintf("~/%s_remoter_auth.rdata", file_prefix);

  # host_ip, host_port
  if (missing(host_ip)){ host_ip <- system2("ipconfig", "/all", stdout = TRUE) |>
  purrr::keep(grepl, pattern = "10[.].+Preferred") |>
  stringi::stri_extract_first_regex("([0-9]{1,3}[.]){3}[0-9]{1,3}")
  }

  if (missing(host_port)){ host_port <- parallelly::freePort() }
  domain_name <- Sys.getenv("USERDOMAIN")
  has_domain <- !identical(domain_name, "")

  # username
  if (missing(username)){
  username <- Sys.getenv("USERNAME")
  } else if (has_domain){
   if (!grepl(domain_name, username)){ username = paste(domain_name, username, sep = "\\") }
  }

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
set_cipher_env %<~% function(cipher = NULL){
#' Set Cipher Environment Variable
#'
#' \code{set_cipher_env}() provides an on-demand method to set the Windows OS environment variables to be used when calling \code{\link{connect_remote}} with \code{credentials = "ENV"}.
#'
#' @param cipher If \code{NULL},the R image holding encryption objects is interactively chosen; otherwise, an object created with \code{\link{make_cipher}}.
#' @export

  if (rlang::is_empty(cipher)){
    rm(cipher)
    load(tcltk::tk_choose.files(multi = FALSE, caption = "Choose the cipher image to load:"));
    cipher <- get(ls(pattern = "cipher", all.names = TRUE));
  }
  .cipher = cipher |> as.character() |> paste(collapse = "")
  .nonce  = attr(cipher, "nonce") |> as.character() |> paste(collapse = "")
  .addr   = attr(cipher, "addr")
  .port   = attr(cipher, "port")
  .skey   = shared_key |> as.character() |> paste(collapse = "")

  rlang::inject(Sys.setenv(
    REMOTER_CIPHER = !!sprintf("%s;%s", .cipher, .nonce)
    , REMOTER_HOST = !!sprintf("%s;%s", .addr, .port)
    , REMOTER_SHARED_KEY = !!.skey
  ))
}
#
connect_remote %<~% function(credentials = NULL, prompt = "REMOTE_SESSION::", port = NULL, action = client, ...){
#' A \code{remoter} Wrapper
#'
#' \code{connect_remote} is a wrapper for \code{remoter::\link[remoter]{client}} making use of predefined encrypted authentication objects
#'
#' @details
#' When \code{credentials} is passed \code{'ENV'}, the following Windows environment variables must already be set:
#' \itemize{
#' \item{\code{REMOTER_CIPHER}: A character representation of the cipher (encrypted password) that can be converted into a raw vector via \code{\link[sodium]{hex2bin}}}
#' \item{\code{REMOTER_SHARED_KEY}: A character representation of the shared key that can be converted into a raw vector via \code{\link[sodium]{hex2bin}}}
#' \item{\code{REMOTER_HOST}: A string of the form "ADDRESS PORT"}
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
        
        action <- rlang::enexpr(action) |> as.character();
        .tmp_env <- new.env(); 
        
        # Create a logical selection vector
        .logivec <- c(`TRUE` = identical(TRUE, credentials)
        			, OS_ENV	= identical("ENV", credentials)
        			, OBJ 		= class(credentials) %in% c("list", "environment")
        			, default = rlang::is_empty(credentials) || TRUE
        			) |> which() |> min();
        
        # Set the local environment 
        eval(rlang::exprs(
        	`TRUE` = .tmp_env %$% {
        		load(tcltk::tk_choose.files(multi = FALSE, caption = "Select the workspace image file containing the cipher and key:"), 
        			envir = .tmp_env)
        		this <- ls(pattern = "cipher", all.names = TRUE)
        		if (length(this) > 1) {
        			this <- tcltk::tk_select.list(choices = this, preselect = this[1], 
        				title = "Choose a cipher object to use: ")
        		}
        		cipher <- rlang::sym(this) |> eval()
        		this <- ls(pattern = "key", all.names = TRUE)
        		if (length(this) > 1) {
        			this <- tcltk::tk_select.list(choices = this, preselect = this[1], 
        				title = "Choose a decryption key object to use: ")
        		}
        		shared_key <- get(this)
        	}
        	, OS_ENV = .tmp_env %$% {
        			cipher <- as.raw(sodium::hex2bin((strsplit(Sys.getenv("REMOTER_CIPHER"), 
        				split = " ", fixed = TRUE)[[1]][[1]])))
        			attr(cipher, "addr") <- strsplit(Sys.getenv("REMOTER_HOST"), 
        				split = " ", fixed = TRUE)[[1]][1]
        			attr(cipher, "port") <- ifelse(is.null(port), as.integer(strsplit(Sys.getenv("REMOTER_HOST"), 
        				split = " ", fixed = TRUE)[[1]][2]), port)
        			attr(cipher, "nonce") <- as.raw(sodium::hex2bin((strsplit(Sys.getenv("REMOTER_CIPHER"), 
        				split = " ", fixed = TRUE)[[1]][[2]])))
        			shared_key <- as.raw(sodium::hex2bin(Sys.getenv("REMOTER_SHARED_KEY")))
        		}
        	, OBJ = {
        			this <- ls(pattern = "cipher", all.names = TRUE, envir = as.environment(credentials))
        			if (length(this) > 1) {
        				this <- tcltk::tk_select.list(choices = this, preselect = this[1], 
        					title = "Choose a cipher object to use: ")
        			}
        			.tmp_env$cipher <- (as.environment(credentials))[[this]]
        			this <- ls(pattern = "key", all.names = TRUE, envir = as.environment(credentials))
        			if (length(this) > 1) {
        				this <- tcltk::tk_select.list(choices = this, preselect = this[1], 
        					title = "Choose a decryption key object to use: ")
        			}
        			.tmp_env$shared_key <- (as.environment(credentials))[[this]]
        		}
        	, default = {
        			message("No valid values for argument 'credentials': exiting ...")
        			return()
        	})[[.logivec]]);
        # Make the call
        rlang::inject(.tmp_env %$% {
        	.fun <- (as.environment("package:remoter")[[!!action]])
        	.args <- { list(
        		  addr = if (stringi::stri_detect_regex(str = attr(cipher, "addr"), max_count = 1, pattern = "([0-9]{1,3}[.]){3}[0-9]{1,3}")){ 
                   # IPV4 format
                   attr(cipher, "addr") 
                 } else { 
                   # Lookup IPV4 address from hostname provided
                   system2(command = "ping", args = c(attr(cipher, "addr"),"-n 1"), stdout = TRUE) |>
                   stringi::stri_extract_first_regex("([0-9]{1,3}[.]){3}[0-9]{1,3}") |> 
                   na.omit() |> unique()
                 }
        			, port = attr(cipher, "port")
        			, password = rawToChar(sodium::data_decrypt(cipher, shared_key))
        			, prompt = !!prompt
        			)}
        	do.call(.fun, .args[intersect(names(formals(.fun)), names(.args))])
        });
        
         # Clean up
        environment() %$% rm(.tmp_env);
}
#
