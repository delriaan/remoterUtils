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

# :: Navigate to the working directory, and Start/stop the session
.dir <- c(stringi::stri_extract_all_regex(.cmd_args, "workdir[=][._/\\a-zA-Z0-9]+") |> 
          stringi::stri_split_fixed("=", simplify = TRUE) |> 
          magrittr::extract(2), "~/")[1]

if (dir.exists(.dir)){ setwd(.dir) } else { setwd("~/") }

# `sessOpts` contains the pre-defined remote session configurations: essentially, a registry
# This is useful for setting ports mapped to sessions under specific execution use cases
# The values of `sessOpts` must map to the prefixes of saved workspace files ending in "remoter_auth.rdata"

# Manually set values for testing purposes
if (FALSE){ 
  .cmd_args <- unique(c(.cmd_args, "action=start", "port=90210", Sys.getenv("COMPUTERNAME") |> make.names() |> tolower())) 
}

options(sessOpts = c(
  Sys.getenv("COMPUTERNAME") |> make.names() |> tolower()
  , Sys.getenv("USERNAME") |> tolower()
  ));

options(thisSession = purrr::as_mapper(~ifelse(rlang::is_empty(.x), getOption("sessOpts")[1], .x[1]))(purrr::keep(.cmd_args, ~.x %in% getOption("sessOpts"))));
if (rlang::is_empty(getOption("thisSession"))){ options(thisSession = Sys.getenv("COMPUTERNAME") |> make.names() |> tolower()) }

# :: Expression-based actions
.cipher <- zMQ.config %$% get(ls(pattern = getOption("thisSession")));
.addr <- if (stringi::stri_detect_regex(str = attr(.cipher, "addr"), max_count = 1, pattern = "([0-9]{1,3}[.]){3}[0-9]{1,3}")){ 
          # IPV4 format
          attr(.cipher, "addr") 
        } else { 
          # Lookup IPV4 address from hostname provided
          system2(command = "ping", args = c(attr(.cipher, "addr"),"-n 1"), stdout = TRUE) |>
          stringi::stri_extract_first_regex("([0-9]{1,3}[.]){3}[0-9]{1,3}") |> 
          na.omit() |> unique()
        }

.port <- .cmd_args[grepl(pattern = "port", x = .cmd_args, ignore.case = TRUE)] |> 
            stringi::stri_split_fixed("=", simplify = TRUE) |> 
            as.vector() |> as.integer() |> magrittr::extract(2);

if (rlang::is_empty(attr(.cipher, "port"))){
  message("Using custom port"); 
  .port <- ifelse(rlang::is.na(.port), parallelly::freePort(), .port)
} else { .port <- attr(.cipher, "port") }

.action <- if (getOption("action") == "start"){
        if (any(stringi::stri_detect_regex(str = system2("netstat", "-an", stdout = TRUE), paste(.addr, .port, sep=":"), max_count = 1L))){
          stop("The requested port is in use.")
        } else {
          # The address of the server is always the machine on which the process is invoked
          rlang::expr(remoter::server(
            port = !!.port
            , password = rawToChar(sodium::data_decrypt(.cipher, shared_key))
            , secure = TRUE, log = TRUE, verbose = TRUE, sync = TRUE
            ))
        }
    } else {
      rlang::expr(remoter::batch(
        addr   = !!.addr
        , port = !!.port
        , password = rawToChar(sodium::data_decrypt(.cipher, shared_key))
        , script = "exit(FALSE)"
        ))
    };

eval(.action, envir = zMQ.config)
