# <<TURN THIS INTO A FUNCTION WITH OUTPUT READABLE BY 'make_batch_file()'>>
# <<ARGUMENTS>>
server_fun <- function(server_dir = "~", sessOpts = c("z_host", Sys.getenv("COMPUTERNAME") |> make.names() |> tolower())){
#' Manage a \code{remoter} Session
#'
#' @param server_dir The path to the authentication objects to read ('.Rdata' files) containing the ciphers and decryption keys.  These should be generated from \code{\link{make_cipher}}
#' @param sessOpts (string[]) Prefixes for the ciphers found in \code{server_dir}

# :: Populate the server environment with authentication data
  if (!"zMQ.config" %in% search()){ 
  attach(new.env(), name = "zMQ.config");
  makeActiveBinding(
  	sym = "zMQ.config"
  	, fun = function(){ invisible(as.environment("zMQ.config")) }
  	, env = as.environment("zMQ.config")
  	);
  }
  
  dir("~", pattern = "remoter_auth.[Rr]data$", full.names = TRUE) |> 
  	purrr::walk(load, envir = zMQ.config, verbose = TRUE);
  
  .cmd_args <- commandArgs(trailingOnly = TRUE);
  
  options(action = ifelse(any(.cmd_args %in% c("action=stop")), "stop", "start"));
  
  # Manually set values for testing purposes
  if (FALSE){ 
    .cmd_args <- unique(c(.cmd_args, "action=start", "port=90210", "session=z_host_hpc", "workdir=C:\\TEMP"))
  }
  
  # :: Navigate to the working directory, and Start/stop the session
  .dir <- c(stri_extract_first_regex(.cmd_args, "workdir[=].+") |> 
            na.omit() |>
            stri_split_fixed("=", simplify = TRUE) |> 
            magrittr::extract(2), "~/")[1]
  
  if (dir.exists(.dir)){ setwd(.dir) } else { setwd("~/") }
  
  # `sessOpts` contains the pre-defined remote session configurations: essentially, a registry
  # This is useful for setting ports mapped to sessions under specific execution use cases
  # The values of `sessOpts` must map to the prefixes of saved workspace files ending in "remoter_auth.rdata"
  
  options(sessOpts = c(
    Sys.getenv("COMPUTERNAME") |> make.names() |> tolower()
    , Sys.getenv("USERNAME") |> tolower()
    , stri_extract_all_regex(.cmd_args, "session[=].+", simplify = TRUE) |> 
        as.vector() |> na.omit() |>
        stri_split_fixed("=", simplify = TRUE, omit_empty = TRUE, tokens_only = TRUE) |> 
        magrittr::extract(2) |>
        purrr::discard(is.na)
    ));
  
  options(thisSession = expand.grid(.cmd_args, getOption("sessOpts")) |> apply(1, purrr::as_mapper(~.x[2][grepl(.x[2], .x[1])])) |> unlist(use.names = FALSE));
  if (rlang::is_empty(getOption("thisSession"))){ options(thisSession = Sys.getenv("COMPUTERNAME") |> make.names() |> tolower()) }
  
  # :: Expression-based actions
  .cipher <- zMQ.config %$% get(ls(pattern = getOption("thisSession")));
  .addr <- if (stri_detect_regex(str = attr(.cipher, "addr"), max_count = 1, pattern = "([0-9]{1,3}[.]){3}[0-9]{1,3}")){ 
            # IPV4 format
            attr(.cipher, "addr") 
          } else { 
            # Look up IPV4 address from hostname provided
            system2(command = "ping", args = c(attr(.cipher, "addr"),"-n 1"), stdout = TRUE) |>
            stri_extract_first_regex("([0-9]{1,3}[.]){3}[0-9]{1,3}") |> 
            na.omit() |> unique()
          }
  
  # Set the port to the first non-empty port available on the system selected from the following:
  .port <- list(
            cipher = attr(.cipher, "port") |> as.integer()
            , custom = {
                stri_extract_first_regex(.cmd_args, pattern = "[Pp][Oo][Rr][Tt][=].+") |>
                stri_split_fixed("=", simplify = TRUE) |> 
                as.vector() |> as.integer() |> 
                magrittr::extract(2) 
              }
            , random = parallelly::freePort()
            ) |> purrr::discard(~{ 
              is.na(.x) | 
              rlang::is_empty(.x) |
              any(grepl(paste(.addr, .x, sep = ":"), system2("psexec64", "\\\\ITDHPC01-D netstat -an", stdout = TRUE)))  
            }) |> magrittr::extract(1) |> unlist();
  
  
  message(sprintf("Using %s port%s", names(.port), ifelse(names(.port) == "random", sprintf(" (%s)", .port), ""))); 
  .port <- unname(.port);
  
  .action <- if (getOption("action") == "start"){
        # The address of the server is always the machine on which the process is invoked
        rlang::expr(remoter::server(
          port = !!.port
          , password = rawToChar(sodium::data_decrypt(get(ls(pattern = paste0(getOption("thisSession"), ".+cipher"))), shared_key))
          , secure = TRUE, log = TRUE, verbose = TRUE, sync = TRUE
          ))
      } else {
        rlang::expr(remoter::batch(
          addr   = !!.addr
          , port = !!.port
          , password = rawToChar(sodium::data_decrypt(get(ls(pattern = paste0(getOption("thisSession"), ".+cipher"))), shared_key))
          , script = "exit(FALSE)"
          ))
      };
  
  eval(.action, envir = zMQ.config)
}