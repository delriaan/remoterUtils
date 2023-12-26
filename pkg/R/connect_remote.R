#' A \code{remoter} Wrapper
#' @description
#' \code{connect_remote} is an R6 class serving as a wrapper for \code{remoter::\link[remoter]{client}} and \code{remoter::\link[remoter]{batch}} making use of predefined encrypted authentication objects. Functionality is designed to work on Windows operating systems.
#' @export
connect_remote <- R6::R6Class(
  classname = "connect_remote"
  , public = { list(
      #' @description
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
      initialize = function(credentials = NULL, prompt = "REMOTE_SESSION", port = NULL, session = make.names(tolower(Sys.getenv("COMPUTERNAME"))), ...){
        force(prompt)
        if (!stringi::stri_detect_regex(prompt, "[:]{2}$")){ prompt <- paste0(prompt, "::") }

        # Which credential type? ----
        .cred_type <- c(
          `TRUE` = identical(TRUE, credentials)
          , OS_ENV	= identical("ENV", credentials)
          , OBJ 		= class(credentials) %in% c("list", "environment")
          , default = rlang::is_empty(credentials) || TRUE
          ) |>
          which() |>
          min();

        # Set the local environment ----
        eval(rlang::exprs(
          `TRUE` = {
              .root <- svDialogs::dlg_dir(
                default = getwd()
                , title = "Choose the directory holding the cipher and key files (created with `make_cipher()`):"
                );

              # browser();

              svDialogs::dlg_list(
                choices = dir(.root$res
                              , pattern = "rdata"
                              , ignore.case = TRUE
                              , full.names = TRUE
                              , all.files = TRUE
                              )
                , title = "Select the workspace image file containing the cipher and key:"
                )$res |>
                load();

              this <- ls(pattern = "cipher", all.names = TRUE);

              if (length(this) > 1){
                this <- svDialogs::dlg_list(
                  choices = this
                  , preselect = this[1]
                  , title = "Choose a cipher object to use: "
                  )
              }
              cipher <- rlang::sym(this) |> eval();
              this <- ls(pattern = "key", all.names = TRUE);

              if (length(this) > 1) {
                this <- svDialogs::dlg_list(choices = this, preselect = this[1], title = "Choose a decryption key object to use: ")
              }
              shared_key <- get(this);
          }
          , OS_ENV = {
              os_env_var <- (\(x){
                x[grepl("remoter", names(x))] |>
                  purrr::map(jsonlite::fromJSON)
                })(Sys.getenv());

              attr(os_env_var, "names") <- stringi::stri_replace_first_fixed(
                  str = names(os_env_var)
                  , pattern = "remoter_"
                  , replacement = ""
                  , vectorize_all = FALSE
                  );

              shared_key <- as.raw(sodium::hex2bin(os_env_var[[session]]$shared_key));
              cipher <- as.raw(sodium::hex2bin(os_env_var[[session]]$cipher));

              attr(cipher, "nonce") <- as.raw(sodium::hex2bin(os_env_var[[session]]$nonce));
              attr(cipher, "addr") <- os_env_var[[session]]$addr;
              attr(cipher, "port") <- os_env_var[[session]]$port;
            }
          , OBJ = {
              this <- ls(pattern = "cipher", all.names = TRUE, envir = as.environment(credentials));

              if (length(this) > 1) {
                this <- svDialogs::dlg_list(
                  choices = this
                  , preselect = this[1]
                  , title = "Choose a cipher object to use: "
                  )
              }
              cipher <- (as.environment(credentials))[[this]];

              this <- ls(pattern = "key", all.names = TRUE, envir = as.environment(credentials));

              if (length(this) > 1) {
                this <- svDialogs::dlg_list(
                  choices = this
                  , preselect = this[1]
                  , title = "Choose a decryption key object to use: "
                  )
                }
              shared_key <- (as.environment(credentials))[[this]]
            }
          , default = {
              message("No valid values for argument 'credentials': exiting ...");
              return();
            }
          )[[.cred_type]]);

        # Set objects in '$private' information ----
        private$.auth <- list(
              addr = attr(cipher, "addr")
              , port = attr(cipher, "port") |> as.integer()
              , password = rawToChar(sodium::data_decrypt(cipher, shared_key))
              );

        # Validate the address ----
        if (rlang::is_empty(hostname2addr(addr = attr(cipher, "addr")))){
          warning(glue::glue("Invalid hostname: {attr(cipher, 'addr')}\nManually set the address using <connect_remote_object>$addr <- \"<address>\""));

          private$.auth$addr <- NULL;
        }

        private$.history <- new.env()

        self$prompt <- prompt;

        # Return ----
        invisible(self);
      },
      #' @description
      #' The print method
      print = function(){
        cat(
          glue::glue("connect_remote <{packageVersion('remoterUtils')}>")
          , if (rlang::is_empty(private$.auth$addr)){
              "Address: <not set>"
            } else {
              glue::glue("Address: {private$.auth$addr}:{private$.auth$port}")
            }
          , glue::glue("Secured: {!rlang::is_empty(private$.auth$password)}")
          , sep = "\n"
          )
      },
      #' @description
      #' The saved authentication objects are used on-demand to make the connection.
      #' @note \itemize{\item{Calling \code{$connect(action=client)} is blocking when capture is \code{TRUE}.} \item{No defaults other than \code{addr}, \code{port}, and \code{password} are provided.}}
      #' @param action (string, symbol) The \code{remoter} function to use to connect to the remote session: \code{client} (default) or \code{batch}.
      #' @param capture (logical) Should the remote output be captured?
      #' @param ... Additional arguments to use.
      #' @return The class environment invisibly: the history is written to class object \code{$history} when \code{capture=TRUE}.
      connect = function(action = "client", capture = FALSE, ...){
        action <- rlang::enexpr(action) |> as.character();

        # Which function to use?
        fun <- match.arg(action, choices = c("client", "batch")) |>
          sprintf(fmt = "remoter::%s") |>
          rlang::parse_expr() |>
          eval();

        args <- rlang::list2(!!!private$.auth, ...);

        if (action == "client"){ args$prompt <- self$prompt }

        # Check whether or not to capture the output:
        if (capture){
          obj_name <- format(Sys.time(), glue::glue("hist_%Y.%m.%d.%H%M%S_{action}"));

          code <- grep(pattern = "file|script", names(args), value = TRUE);

          result <- capture.output(do.call(what = fun, args = args), split = capture) |>
            paste(collapse = "\n");

          assign(x = obj_name, mget(c("code", "result")), envir = private$.history);
        } else {
          do.call(what = fun, args = args);
        }

        invisible(self)
      },
      #' @field prompt A string to use as the prompt when connecting interactively to a remote session (defaults to "REMOTE_SESSION")
      prompt = NULL
    )}
  , active = { list(
      #' @field history Returns an environment object from which the history of captured connection output can be accessed
      history = function(){
        if (private$.history |> ls() |> rlang::is_empty()){
          message("No entries in history (try calling method '$connect(action, capture=TRUE)' from the class object.)")
          invisible()
        } else {
          invisible(private$.history)
        }
      },
      #' @field addr The existing value or the new value.
      addr = function(value){
        if (missing(value)){
          invisible(private$.auth$addr)
        } else {
          private$.auth$addr <- value
        }
      },
      #' @field port The existing value or the new value.
      port = function(value){
        if (missing(value)){
          invisible(private$.auth$port)
        } else {
          private$.auth$port <- value
        }
      },
      #' @field password The existing value or the new value.
      password = function(value){
        if (missing(value)){
          invisible(private$.auth$password)
        } else {
          private$.auth$password <- value
        }
      }
      )
  }
  , private = list(.auth = NULL, .history = NULL)
  )
