server_fun <- function(auth_root = path.expand("~"), server_dir = "~", session = make.names(tolower(hostname())), ...){
  #' Manage a \code{remoter} Session
  #'
  #' \code{server_fun} starts or stops a \code{remoter} session (see \code{\link[remoter]{remoter-package}} for documentation).
  #'
  #' @param auth_root The path to the authentication objects to read ('.rdata' files) containing the ciphers and decryption keys. These should be generated from \code{\link{make_cipher}}
  #' @param server_dir The path to the working directory for the spawned server
  #' @param session (string) The session prefix for the ciphers loaded from \code{auth_root}
  #' @param ... \code{\link[rlang]{dots_list}}: additional arguments passed externally
  #'
  #' @note Designed for Windows OS
  #'
  #' @importFrom pbdZMQ ls
  #'
  #' @export
    
    .dot_args <- as.character(rlang::enexprs(...)) |> unlist();
    chatty <- "trace" %in% .dot_args;
    options(action = ifelse(any(grepl("action[=]stop", .dot_args)), "stop", "start"));
  
    alt_server_dir <- NULL
    zMQ.config <- environment()

    # :: Helper function
      get_pass <- \(x, y){
        rawToChar(sodium::data_decrypt(bin = zMQ.config[[paste0(x, "_cipher")]], key = y))
        }
    #
    # :: Execution message templates
      exec_messages <- list(
        info_msg_1 = "Populate the server environment with authentication data"
        , err_msg_1 = "No authentication file found in the root directory. \nGenerate the requisite file using `remoterUtils::make_cipher()`\nExiting ..."
        , info_msg_2 = "Navigating to the working directory and set the session"
        , warn_msg_1 = "Working directory {alt_server_dir} does not exist: trying '{server_dir}' ..."
        , warn_msg_2 = "Working directory {alt_server_dir} does not exist: using '~/' ..."
        , info_msg_3 = "Processing expression-based actions"
        , info_msg_4 = "Starting remote session ..."
        )
    #
    # :: Populate the server environment with authentication data ----
      if (chatty){ cli::cli_alert_info(info_msg_1) }

      .auth_image <- dir(auth_root, pattern = glue::glue("{session}.+remoter_auth.[Rr]data$"), full.names = TRUE)
      if (rlang::is_empty(.auth_image)){
        cli::abort(err_msg_1)
      }
      purrr::walk(.auth_image, load, envir = zMQ.config, verbose = TRUE);
    
    #
    # :: Navigate to the working directory and set the session ----
      if (chatty){ cli::cli_alert_info(info_msg_2) }

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
          cli::cli_alert_warning(glue::glue(warn_msg_1));
          if (dir.exists(server_dir)){
            setwd(server_dir)
          } else {
            cli::cli_alert_info(glue::glue(warn_msg_2));
            setwd("~/");
          }
        }
      } else if (!rlang::is_empty(server_dir)){
        if (dir.exists(server_dir)){
          setwd(server_dir)
        } else {
          cli::cli_alert_warning(glue::glue(warn_msg_2));
          setwd("~/");
        }
      } else {
        cli::cli_alert_info("Working directory set to '~/' ...");
        setwd("~/");
      }

      if (rlang::is_empty(session)){ session <- make.names(tolower(hostname())) }

    #
    # :: Expression-based actions ----
      if (chatty){ cli::cli_alert_info(info_msg_3) }

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

      cli::cli_alert_info(sprintf("Using %s port%s", names(.port), ifelse(names(.port) == "random", sprintf(" (%s)", .port), "")));

      .port <- unname(.port);

      .logfile <- glue::glue("{getwd()}/.{session}_remote_session.log")

      .action <- if (getOption("action") == "start"){
          rlang::expr(remoter::server(
            port = !!.port
            , password = !!get_pass(session, shared_key)
            , log = .logfile
            , secure = TRUE
            , showmsg = TRUE
            , verbose = TRUE
            , sync = TRUE
            ))
        } else {
          rlang::expr(remoter::batch(
            addr = !!.addr
            , port = !!.port
            , password = !!get_pass(session, shared_key)
            , script = "exit(FALSE)"
            ))
          unlink(glue::glue("{getwd()}/.Rhistory"));
        }

    #
    # :: Start/stop the remote session ----
      if (chatty){ message(info_msg_4) }

      setwd(tempdir());

      eval(.action)
}
