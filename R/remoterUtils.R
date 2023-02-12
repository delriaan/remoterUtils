#' @title Utility Functions for \code{remoter}
#'
#' @description
#' \code{remoterUtils} provides utility functions facilitating management of \code{remoter} sessions as well as authentication objects (see \code{\link[remoter]{remoter-package}} for \code{remoter} documentation).  Code is designed for use in a Windows environment.
#'
#' @name remoterUtils-package
NULL

gen_pass <- function(glyphs = "@$", length = NULL, raw = FALSE, chatty = FALSE){
#' Generate a Password
#'
#' \code{gen_pass} creates a password consisting of alphanumeric glyphs and symbols
#'
#' @param glyphs Character-coercibles to use in the creation of the password: this is combined with the output of \code{\link[sodium]{keygen}}
#' @param length (int) The length of the password in character format
#' @param raw (logical) Should the output be returned as raw?
#' @param chatty (logical) Should diagnostic information be provided?
#'
#' @note The generated string always begins with a letter before being returned as-is or returned as a raw vector
#' @export

	set.seed(Sys.time());

  force(glyphs);

  glyphs <- { c(sodium::keygen(), LETTERS, glyphs) |>
      stringi::stri_extract_all_regex(".", simplify = TRUE) |>
      as.vector() |>
      purrr::keep(~.x != "") |>
      table()
    }

  .sample_wgt <- c(.75, 1, .5);

  sample_glyphs <- purrr::as_mapper(~{
    .this <- { ifelse(
        grepl("[0-9A-Z]", names(.x))
        , .x * .sample_wgt[1]
        , ifelse(
            grepl("[a-z]", names(.x))
            , .x * .sample_wgt[2]
            , .x * .sample_wgt[3]
            )) * (3/.x)
      } |>
      ceiling() |>
      purrr::imap(~rep.int(.y, .x)) |>
      unlist(use.names = FALSE);

    sample(
      x = .this
      , size = ifelse(rlang::is_empty(length), length(.this), length)
      , replace = TRUE
      , prob = c(table(.this))[.this]
      ) |>
      paste(collapse = "") |>
      stringi::stri_extract_all_regex(pattern = ".", simplify = TRUE) |>
      as.vector();
  });

  .out <- sample_glyphs(glyphs);
  .alpha_r <- sum(.out %in% letters) / length(.out);
  .ALPHA_r <- sum(.out %in% LETTERS) / length(.out);
  .alpha_ratio <- abs(.alpha_r - .ALPHA_r);

  .iter <- 0;

  while((.alpha_ratio > .10) & (.iter < 1000L)){
    set.seed(sample(.Random.seed, 1));

    .out <- sample_glyphs(glyphs);
    .alpha_r <- sum(.out %in% letters) / length(.out);
    .ALPHA_r <- sum(.out %in% LETTERS) / length(.out);
    .ALPHA_r <- sum(.out %in% LETTERS) / length(.out);
    .alpha_ratio <- abs(.alpha_r - .ALPHA_r);
    .iter <- .iter + 1
  }

  if (chatty){ message(glue::glue("\nPassword generated with replication \ntries: {.iter}\nalpha_ratio:{.alpha_ratio}")) }

  .out <- paste(c(sample(c(letters,LETTERS), 1), .out), collapse = "");

  if (raw){ charToRaw(.out) } else { .out }
}
#
make_cipher <- function(file_prefix = make.names(tolower(Sys.getenv("COMPUTERNAME"))), host_ip , host_port, password, shared_key, export = FALSE){
#' Create \code{remoter} Authorization Objects
#'
#' \code{remoter_auth} creates an encrypted object used to securely start and connect to a \code{\link[remoter]{remoter}} session
#'
#' @param file_prefix (string) The prefix for the output file in the user directory having suffix "_remoter_auth.rdata"
#' @param host_ip (string) The IPV4 address for the server (hostnames are not allowed)
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

  # host_ip, host_port
  if (missing(host_ip)){ host_ip <- system2("ipconfig", "/all", stdout = TRUE) |>
    purrr::keep(grepl, pattern = "10[.].+Preferred") |>
    stringi::stri_extract_first_regex("([0-9]{1,3}[.]){3}[0-9]{1,3}")
    }

  if (missing(host_port)){ host_port <- parallelly::freePort() }
  domain_name <- Sys.getenv("USERDOMAIN")
  has_domain <- !identical(domain_name, "")

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
#
make_batch_file <- function(server_dir, auth_root, batch.file_name = "start_Rserver.bat", source.file_name = "Rserve.R", session = make.names(tolower(Sys.getenv("COMPUTERNAME")))){
#' Make a \code{remoter} Server Batch File
#'
#' @param server_dir (string) The server working directory
#' @param auth_root (string) The path to the authentication objects
#' @param batch.file_name (string) The name of the batch file to be created in \code{server_dir}
#' @param source.file_name (string) The name of the R source file to be created in \code{server_dir}
#' @param session (string) The session label for the spawned server: must match the cipher object that is ultimately loaded
#' @references \href{https://superuser.com/questions/149951/does-in-batch-file-mean-all-command-line-arguments}
#'
#' @note Existing contents in \code{server_dir} are deleted before repopulating
#' @return \code{source.file_name} and \code{batch.file_name} (which calls \code{source.file_name}) created in \code{server_dir}
#'
#' @export

  if (missing(server_dir)){
    server_dir <- if (interactive()){
      tcltk::tk_choose.dir(default = path.expand("~"), caption = "Select destination directory for Rserver control files:")
    } else { path.expand("~") }
  }

  if (missing(auth_root)){
    auth_root <- if (interactive()){
      tcltk::tk_choose.dir(default = path.expand("~"), caption = "Select source directory for Rserver authentication files:")
    } else { path.expand("~") }
  }

  if (!dir.exists(server_dir)){
    pass <- dir.create(server_dir)
    if (pass){
      glue::glue("Created {server_dir}") |> message()
    } else {
      stop(glue::glue("Failed to create {server_dir}"))
    }
  }

  purrr::walk(dir(server_dir, full.names = TRUE), unlink);

  cat(glue::glue("@echo off\nRscript -e \"source('{server_dir}/{source.file_name}')\" --args %%*"), file = paste(server_dir, batch.file_name, sep = "/"));

  cat(glue::glue("library(remoterUtils); \nserver_fun(auth_root = \"{auth_root}\", server_dir = \"{server_dir}\", session = \"{session}\", !!!commandArgs(trailingOnly = TRUE))"), file = paste(server_dir, source.file_name, sep = "/"), append = FALSE)

}
#
connect_remote <- function(credentials = NULL, prompt = "REMOTE_SESSION::", port = NULL, action = client, session = make.names(tolower(Sys.getenv("COMPUTERNAME"))), ...){
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
#
server_fun <- function(auth_root = path.expand("~"), server_dir = "~", session = make.names(tolower(Sys.getenv("COMPUTERNAME"))), ...){
#' Manage a \code{remoter} Session
#'
#' \code{server_fun} starts or stops a \code{\link[remoter]{remoter}} session
#'
#' @param auth_root The path to the authentication objects to read ('.Rdata' files) containing the ciphers and decryption keys.  These should be generated from \code{\link{make_cipher}}
#' @param server_dir The path to the working directory for th spawned server
#' @param session (string) The session prefix for the ciphers loaded from \code{auth_root}
#' @param ... \code{\link[rlang]{dots_list}}: additional arguments passed externally
#'
#' @export

  .dot_args <- as.character(rlang::enexprs(...)) |> unlist();
  chatty <- "trace" %in% .dot_args;
  alt_server_dir <- NULL;
  get_pass <- purrr::as_mapper(~{ rawToChar(sodium::data_decrypt(bin = zMQ.config[[paste0(.x, "_cipher")]], key = .y)) });

  options(action = ifelse(any(grepl("action[=]stop", .dot_args)), "stop", "start"));

  # :: Populate the server environment with authentication data ----
  if (chatty){ message("Populate the server environment with authentication data") }
  if (!"zMQ.config" %in% search()){
  attach(new.env(), name = "zMQ.config");

  makeActiveBinding(
  	sym = "zMQ.config"
  	, fun = function(){ invisible(as.environment("zMQ.config")) }
  	, env = as.environment("zMQ.config")
  	);
  }

  dir(auth_root, pattern = glue::glue("{session}.+remoter_auth.[Rr]data$"), full.names = TRUE) |>
  	purrr::walk(load, envir = zMQ.config, verbose = TRUE);

  # :: Navigate to the working directory and set the session ----
  if (chatty){ message("Navigate to the working directory and set the session") }
  if (any(grepl("workdir[=]", .dot_args))){
    alt_server_dir <- c(stringi::stri_extract_first_regex(.dot_args, "workdir[=].+") |>
      na.omit() |>
      stringi::stri_split_fixed("=", simplify = TRUE) |>
      magrittr::extract(2), "~/")[1]
  }
  if (!rlang::is_empty(alt_server_dir)){
    if (dir.exists(alt_server_dir)){
      setwd(alt_server_dir)
    } else {
      message(glue::glue("Working directory {alt_server_dir} does not exist: trying '{server_dir}' ..."));
      if (dir.exists(server_dir)){
        setwd(server_dir)
      } else {
        message(glue::glue("Working directory {alt_server_dir} does not exist: using '~/' ..."));
        setwd("~/");
      }
    }
  } else if (!rlang::is_empty(server_dir)){
    if (dir.exists(server_dir)){
      setwd(server_dir)
    } else {
      message(glue::glue("Working directory {alt_server_dir} does not exist: using '~/' ..."));
      setwd("~/");
    }
  } else{
    message("Working directory set to '~/' ...");
    setwd("~/");
  }

  if (rlang::is_empty(session)){ session <- make.names(tolower(Sys.getenv("COMPUTERNAME"))) }

  # :: Expression-based actions ----
  if (chatty){ message("Expression-based actions") }

  cipher <- get(glue::glue("{session}_cipher"), envir = zMQ.config);
  .addr <- attr(cipher, "addr");

  # Set the port to the first non-empty port available on the system selected from the following:
  .port <- list(
      cipher = attr(cipher, "port") |> as.integer()
      , custom = {
          stringi::stri_extract_first_regex(.dot_args, pattern = "[Pp][Oo][Rr][Tt][=].+") |>
          stringi::stri_split_fixed("=", simplify = TRUE) |>
          as.vector() |> as.integer() |>
          magrittr::extract(2)
        }
      , random = parallelly::freePort()
      ) |> purrr::discard(~{
        is.na(.x) |
        rlang::is_empty(.x)
        # STUB: need port scanner code here, 2023.02.12
      }) |>
      magrittr::extract(1) |>
      unlist();

  message(sprintf("Using %s port%s", names(.port), ifelse(names(.port) == "random", sprintf(" (%s)", .port), "")));
  .port <- unname(.port);

  .action <- if (getOption("action") == "start"){
      rlang::expr(remoter::server(port = !!.port, password = !!get_pass(session, shared_key), secure = TRUE, log = TRUE, verbose = TRUE, sync = TRUE))
    } else {
      rlang::expr(remoter::batch(addr = !!.addr, port = !!.port, password = !!get_pass(session, shared_key), script = "exit(FALSE)"))
    }

  # :: Start/stop the remote session ----
  if (chatty){ message("Starting remote session ...") }
  eval(.action, envir = zMQ.config)
}
#
hostname2addr <- function(addr, ipver = 4){
#' Get the IP Address from a Hostname
#'
#' \code{hostname2addr} pings \code{hostname} and parses the response to get the address
#'
#' @param addr (string) The hostname: if an IP address, the function serves as a form of address accessibility
#' @param ipver (integer | 4) The IP protocol version to use
#'
#' @export

  system2(command = "ping", args = c(addr,glue::glue("-n 1 -{ipver}")), stdout = TRUE) |>
    stringi::stri_extract_first_regex("([0-9]{1,3}[.]){3}[0-9]{1,3}") |>
    na.omit() |> unique()
}
#
