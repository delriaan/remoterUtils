# <<TURN THIS INTO A FUNCTION WITH OUTPUT READABLE BY 'make_batch_file()'>>
# <<ARGUMENTS>>
server_fun <- function(server_dir = "~", sessOpts = c("z_host", Sys.getenv("COMPUTERNAME") |> make.names() |> tolower())){
#' Manage a \code{remoter} Session
#'
#' @param server_dir The path to the authentication objects to read ('.Rdata' files) containing the ciphers and decryption keys.  These should be generated from \code{\link{make_cipher}}
#' @param sessOpts (string[]) Prefixes for the ciphers found in \code{server_dir}

  # :: Populate the server environment with authentication data
  .cmd_args <- commandArgs(trailingOnly = TRUE);
  if (!"zMQ.config" %in% search()){
    attach(new.env(), name = "zMQ.config");
    makeActiveBinding(
    	sym = "zMQ.config"
    	, fun = function(){ invisible(as.environment("zMQ.config")) }
    	, env = as.environment("zMQ.config")
    	);
  }

  # Manually set values for testing purposes
  if (FALSE){ .cmd_args <- unique(c(.cmd_args, "action=start", ".imperial")) }

  action <- ifelse(any(.cmd_args %in% c("action=stop")), "stop", "start");

  # @param sessOpts Contains the pre-defined remote session configurations: essentially, a registry
  # This is useful for setting ports mapped to sessions under specific execution use cases
  # The values of `sessOpts` must map to the prefixes of saved workspace files ending in "remoter_auth.rdata"

  thisSession <- purrr::as_mapper(~ifelse(rlang::is_empty(.x), "z_host", .x[1]))(purrr::keep(.cmd_args, ~.x %in% sessOpts));

  dir(path = server_dir, pattern = "[Rr]data$", full.names = TRUE, all.files = TRUE) |>
  	purrr::walk(load, envir = zMQ.config, verbose = TRUE);

  # :: Expressions
  .cipher_name <- sprintf("(%s).+cipher$", paste(thisSession, collapse = "|"));
  .server_name <- paste0(thisSession, "_server");
  .session_config <- rlang::inject(mget(ls(zMQ.config, pattern = !!.cipher_name, all.names = TRUE), envir = zMQ.config) |> purrr::set_names(!!.server_name));
  .port <- .cmd_args[grepl(pattern = "port", x = .cmd_args, ignore.case = TRUE)];

  .action_list <- purrr::imap(.session_config, ~{
      if (action == "start"){
        if (any(stringi::stri_detect_regex(system2("netstat", "-an", stdout = TRUE), paste0(attr(.x, "port"), ".+LISTENING")))){
            message("The requested port is in use.")
          } else {
            rlang::expr(remoter::server(
              port = !!ifelse(
                        rlang::is_empty(attr(.x, "port"))
                        # No cipher attribute
                        , ifelse(
                            rlang::is_empty(.port)
                            # No command-line argument
                            , { message("Using random port"); parallelly::freePort() }
                            , { message("Using custom port"); strsplit(.port, split = "=")[[1]][2] |> as.integer() }
                            )
                        , attr(.x, "port")
                        )
              , password = rawToChar(sodium::data_decrypt(!!.x, shared_key))
              , secure = TRUE, log = TRUE, verbose = TRUE, sync = TRUE
              ))
          }
      } else {
        rlang::expr(remoter::batch(
          addr   = !!attr(.x, "addr")
          , port = !!ifelse(
                      rlang::is_empty(attr(.x, "port"))
                      # No cipher attribute
                      , { message("Using custom port");
                      		strsplit(.port, split = "=")[[1]][2] |> as.integer()
                      	}
                      , attr(.x, "port")
                      )
          , password = rawToChar(sodium::data_decrypt(!!.x, shared_key))
          , script   = "exit(FALSE)"
          ))
      }
    });

  # :: Start/stop the session
  eval(.action_list[[1]], envir = zMQ.config)
}
