hostname <- \(x = NULL){
  #' Create a Hostname
  #' 
  #' @param x (name|string) The name of the host
  #' 
  #' @return A string for use with \code{\link{make_cipher}}
  #' @export
  x <- rlang::enexpr(x)

  ifelse(    
    rlang::is_empty(x)
    , ifelse(
        grepl("Windows", osVersion)
        , Sys.getenv("COMPUTERNAME")
        , "localhost"
        )
    , as.character(x) |> _[1] |> make.names()
    )
}

make_cipher <- function(file_prefix = hostname(), hostname = hostname(), host_ip , host_port, password, shared_key, export = FALSE){
  #' Create \code{remoter} Authorization Objects
  #'
  #' \code{make_cipher} creates an encrypted object used to securely start and connect to a \code{remoter} session (see \code{\link[remoter]{remoter-package}} for documentation)
  #'
  #' @param file_prefix (string) The prefix for the output file in the user directory having suffix "_remoter_auth.rdata"
  #' @param hostname (string) The label to use for the server
  #' @param host_ip (string) \emph{(required)} The IPV4 address for the server (hostnames are not allowed).
  #' @param host_port (string,integer) \emph{(required)} The port to use for the server: should be a static, reserved port
  #' @param password (string) \emph{(required)} The password for the server
  #' @param shared_key (string) \emph{(required)} The key to encrypt and decrypt the generated cipher
  #' @param export (logical | \code{FALSE}) When \code{TRUE}, the cipher will be saved to the user directory as "~/"\code{file_prefix}_\code{remoter_auth.rdata}"
  #'
  #' @return The cipher (invisibly) having required attributes \code{nonce}, \code{port}, and \code{addr}
  #'
  #' @export

  file_prefix <- rlang::enexpr(file_prefix) |> as.character()
  hostname <- rlang::enexpr(file_prefix) |> as.character()
  
  if (missing(host_ip)){
    cli::cli_alert_danger("Missing argument 'host_ip': exiting ...")
    return(NULL)
  } else {
    host_ip <- rlang::enexpr(host_ip) |> as.character()

    if (!stringi::stri_detect_regex(host_ip, "([0-9]{1,3}[.]){3}[0-9]{1,3}")){
      host_ip <- hostname2addr(host_ip, ipver = 4)

      if (rlang::is_empty(host_ip)){
        cli::cli_alert_danger("Could not determine a host IP: exiting ...")
        return(NULL)
      }
    }
  }

  .cipher_name <- paste0(file_prefix, "_cipher") |> tolower()
  .file_name  <- sprintf("~/%s_remoter_auth.rdata", file_prefix) |> tolower()

  # password:
    if (missing(password)){
      password <- askpass::askpass(prompt = "Enter text to use as the server password:")
    } else if (rlang::is_empty(password)){
      password <- askpass::askpass(prompt = "Enter text to use as the server password:")
    } else {
      password <- rlang::enexpr(password) |> as.character()
      if (length(password) > 1){
        cli::cli_alert_danger("Password must be of length 1L: exiting ...")
        return(NULL)
      }
      cli::cli_alert_info("Valid type for `password` detected ... ")
    }

  # shared_key:
    if (missing(shared_key)){
      shared_key <- askpass::askpass(prompt = "Enter text to use as the cipher shared key:")
    } 
    
    shared_key <- switch(
      class(shared_key)
      , character = paste(shared_key, collapse = "") |> charToRaw()
      , raw = shared_key
      , { cli::alert_danger("The value type for `shared_key` must be 'character' or 'raw': exiting ...")
          return(NULL)
        }
      ) |>
      sodium::sha256()
    
    cli::cli_alert_info("Valid type for `shared_key` detected ... ")

  # .nonce:
    .nonce <- paste(hostname, Sys.time(), sep = "::") |>
      charToRaw() |>
      magrittr::extract(1:24);

  # Intermmediate step:
    assign(.cipher_name, {
      sodium::data_encrypt(msg = charToRaw(password), key = shared_key, nonce = .nonce) |>
      magrittr::set_attr("nonce", .nonce) |>
      magrittr::set_attr("hostname", hostname) |>
      magrittr::set_attr("port" , host_port) |>
      magrittr::set_attr("addr" , host_ip)
      }, envir = environment());

  # Export/Return:
    if (export){
      if (file.exists(.file_name)){ 
        file.rename(
          .file_name
          , sprintf("%s_%s.old", .file_name, format(Sys.time(), "%Y%m%d_%H%M%S"))
          )
      }

      save(
        file = .file_name
        , list = c(.cipher_name, "shared_key")
        , compress = "bzip2"
        , eval.promises = TRUE
        , precheck = TRUE
        )
    }
  
    invisible(rlang::sym(.cipher_name) |> eval());
}

make_cipher_env <- function(cipher = NULL, shared_key = NULL, session = make.names(tolower(Sys.getenv("COMPUTERNAME"))), set_env = FALSE){
  #' Make a Cipher OS Environment Variable
  #'
  #' \code{make_cipher_env}() creates anenvironment variable string from the provided cipher. OS environment variables beginning with 'remoter_' and ending with the target session string are searched when calling \code{\link{connect_remote}} with \code{credentials = "ENV"}.
  #'
  #' @param cipher If \code{NULL},the R image holding encryption objects is interactively chosen; otherwise, an object created with \code{\link{make_cipher}}.
  #' @param shared_key If the shared key was not included in the cipher object, this value is checked and throws an error if empty
  #' @param session The name of the session for which the environment variable string is created
  #' @param set_env (logical) Should an environment variable be set for the current session?
  #'
  #' @return a JSON string that can be stored in an environment variable formatted as "remoter_<session>"
  #'
  #' @export

    # :: Messages
      .messages <- list(
        cipher = "Choose the index of the cipher object file to use: "
        , decryption_key = "Choose the index of the decryption key object to use: "
        , no_shared_key = "No shared key was found for the supplied cipher: exiting ..."
        )
    # ::
    if (rlang::is_empty(cipher)){
      cli::cli_alert_info(.messages$cipher)
      cipher <- file.choose()
      load(cipher, envir = environment())

      cipher <- get(ls(pattern = paste0(session, ".+cipher")));
    }

    if (class(cipher) %in% c("environment", "list")){
      .tmp_env <- as.environment(cipher);
      
      # Cipher
        this <- ls(pattern = "cipher", all.names = TRUE, envir = .tmp_env)

        if (length(this) > 1) { 
          .i <- readline(.messages$cipher) |> as.integer()
          if (.i == "" || !is.numeric(.i) || .i < 1L){ .i <- 1 }
        }
      
        cipher <- .tmp_env[[this[.i]]];

      # Decryption Key
        this <- ls(pattern = "key", all.names = TRUE, envir = .tmp_env)
        
        if (length(this) > 1) { 
          .i <- readline(.messages$decryption_key) |> as.integer()
          if (.i == "" || !is.numeric(.i) || .i < 1L){ .i <- 1 }
        }
      
        shared_key <- .tmp_env[[this[.i]]]
    }

    if (rlang::is_empty(shared_key)){ 
      cli::cli_alert_danger(.messages$no_shared_key) 
      return(NULL)
    }
  
  # :: Return
    nonce  = attr(cipher, "nonce")
    addr   = attr(cipher, "addr")
    port   = attr(cipher, "port")

    .out = tryCatch({
      rlang::list2("remoter_{session}" := mget(ls()) |> 
        purrr::map(paste, collapse = "") |> 
        jsonlite::toJSON()
        ) |> 
        unlist()
      }, error = \(e) e)
    
    if (!rlang::is_empty(.out)){
      if (set_env) eval(str2lang(glue::glue("Sys.setenv({names(.out)[1]} = {shQuote(as.vector(.out)[1])})")))
      
      return(.out)
    } else { 
      cli::cli_alert_danger("Error creating output:")
      cli::cli_alert_danger(.out)
      return(NULL)
    }
}
