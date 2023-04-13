server_fun <- function(auth_root = path.expand("~"), server_dir = "~", session = make.names(tolower(Sys.getenv("COMPUTERNAME"))), ...){
#' Manage a \code{remoter} Session
#'
#' \code{server_fun} starts or stops a \code{remoter} session (see \code{\link[remoter]{remoter-package}} for documentation).
#'
#' @param auth_root The path to the authentication objects to read ('.rdata' files) containing the ciphers and decryption keys.  These should be generated from \code{\link{make_cipher}}
#' @param server_dir The path to the working directory for th spawned server
#' @param session (string) The session prefix for the ciphers loaded from \code{auth_root}
#' @param ... \code{\link[rlang]{dots_list}}: additional arguments passed externally
#'
#' @export
  if (!"zMQ.config" %in% search()){ attach(new.env(), name = "zMQ.config") }

  alt_server_dir <- NULL;

  .dot_args <- as.character(rlang::enexprs(...)) |> unlist();

  chatty <- "trace" %in% .dot_args;

  get_pass <- function(x, y){ rawToChar(sodium::data_decrypt(bin =  as.environment("zMQ.config")[[paste0(x, "_cipher")]], key = y)) }

  options(action = ifelse(any(grepl("action[=]stop", .dot_args)), "stop", "start"));

  # :: Populate the server environment with authentication data ----
  if (chatty){ message("Populate the server environment with authentication data") }

  dir(auth_root, pattern = glue::glue("{session}.+remoter_auth.[Rr]data$"), full.names = TRUE) |>
  	purrr::walk(load, envir = as.environment("zMQ.config"), verbose = TRUE);

  # :: Navigate to the working directory and set the session ----
  if (chatty){ message("Navigate to the working directory and set the session") }

  if (any(grepl("workdir[=]", .dot_args))){
    alt_server_dir <- c(stringi::stri_extract_first_regex(.dot_args, "workdir[=].+") |>
      stats::na.omit() |>
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

  cipher <- eval(rlang::sym(glue::glue("{session}_cipher")));
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
      ) |>
      purrr::discard(\(x) is.na(x) | rlang::is_empty(x)) |>
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

  eval(.action)
}
