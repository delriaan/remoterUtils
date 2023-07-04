# source("R/!MAIN.R")
# mget(ls()) |> purrr::walk(debug);
# library(remoterUtils)

#
# make_cipher() |> make_cipher_env() ----
# shared_key <- book.of.utilities::gen.pass(glyphs = "@:_.", length = 50, raw = TRUE) |> sodium::sha256();

cipher_env <- { remoterUtils::make_cipher(
  file_prefix = "imperialtower"
  , host_ip = "IMPERIALTOWER"
  , host_port = 65000
  , shared_key = shared_key
  , password = book.of.utilities::gen.pass(glyphs = "$_!.", length = 20)
  , export = TRUE
  ) } |> remoterUtils::make_cipher_env(shared_key = shared_key, session = "imperialtower")

rm(cipher_env);

cipher_env <- { remoterUtils::make_cipher(
  file_prefix = "GW2"
  , host_ip = "IMPERIALTOWER"
  , host_port = 65001
  , shared_key = shared_key
  , password = book.of.utilities::gen.pass(glyphs = "$_!.", length = 20)
  , export = TRUE
  )} |> remoterUtils::make_cipher_env(shared_key = shared_key, session = "GW2")

#
Sys.getenv("remoter_imperialtower") |> jsonlite::fromJSON()
Sys.getenv("remoter_GW2") |> jsonlite::fromJSON()
#
# make_batch_file() ----
remoterUtils::make_batch_file(
  server_dir = Sys.getenv("remoter_imperialtower")
  , auth_root = path.expand("~")
  , batch.file_name = "start.bat"
  , source.file_name = "start.R"
  , session = "imperialtower"
  )

remoterUtils::make_batch_file(
  server_dir = Sys.getenv("remoter_GW2")
  , auth_root = path.expand("~")
  , batch.file_name = "start.bat"
  , source.file_name = "start.R"
  , session = "GW2"
  )

#
# connect_remote() ----
# debug(remoterUtils::connect_remote)
X <- remoterUtils::connect_remote$new(credentials = TRUE, prompt = "IMPERIALTOWER", session = "imperialtower")
print(X)
X$prompt
X$history
X$connect(capture = TRUE)
search()
exit()
X$connect(action = batch, script="search()", capture = TRUE)
X$history %$% mget(ls())
# connect_remote(credentials = 'ENV', prompt = "GW2::", session = "GW2")
#
# server_fun ----
# debug(server_fun)
# remoterUtils::server_fun(server_dir = Sys.getenv("remoter_imperialtower"), session = "imperialtower")
#
# pkgdown ----
# usethis::use_pkgdown()
# pkgdown::build_site(pkg = "pkg", lazy = TRUE, override = list(destination = "../docs"))
