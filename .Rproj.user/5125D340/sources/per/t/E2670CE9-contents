# source("R/!MAIN.R")
# mget(ls()) |> purrr::walk(debug);
# library(remoterUtils)

# gen_pass() ----
gen_pass(length = 30);
gen_pass(length = 30, glyphs = "#=)_$");
gen_pass(length = 30, glyphs = "#=)_$", raw = TRUE);

#
# make_cipher() |> make_cipher_env() ----
shared_key <- gen_pass(glyphs = "@:_.", length = 50, raw = TRUE) |> sodium::sha256();

cipher_env <- { make_cipher(
  file_prefix = "imperialtower"
  , host_ip = "IMPERIALTOWER"
  , host_port = 65000
  , shared_key = shared_key
  , password = gen_pass(glyphs = "$_!.", length = 20)
  , export = TRUE
  ) }|> make_cipher_env(shared_key = shared_key)

rm(cipher_env);

cipher_env <- { make_cipher(
  file_prefix = "GW2"
  , host_ip = "IMPERIALTOWER"
  , host_port = 65001
  , shared_key = shared_key
  , password = gen_pass(glyphs = "$_!.", length = 20)
  , export = !TRUE
  )} |> make_cipher_env(shared_key = shared_key, session = "GW2")

#
Sys.getenv("remoter_imperialtower") |> jsonlite::fromJSON()
Sys.getenv("remoter_GW2") |> jsonlite::fromJSON()
#
# make_batch_file() ----
make_batch_file(
  server_dir = "D:/remoter_imperialtower"
  , auth_root = path.expand("~")
  , batch.file_name = "start.bat"
  , source.file_name = "start.R"
  , session = "imperialtower"
  )
make_batch_file(
  server_dir = "D:/remoter_GW2"
  , auth_root = path.expand("~")
  , batch.file_name = "start.bat"
  , source.file_name = "start.R"
  , session = "GW2"
  )

#
# connect_remote() ----
remoterUtils::connect_remote(credentials = 'ENV', prompt = "IMPERIAL::", session = "imperialtower")
# connect_remote(credentials = 'ENV', prompt = "GW2::", session = "GW2")

remoter::client(addr = "IMPERIALTOWER", port = 65000, prompt = "IMPERIAL::"
                , password = sodium::data_decrypt(
                              bin = sodium::hex2bin("0c4773443df1f630f38f2f6731e3a76ec5185e845f5fae311fcbfd7c1b0666e66f7628f429")
                              , nonce = sodium::hex2bin("494d50455249414c544f5745523a3a313637363231323236")
                              , key = sodium::hex2bin("eec3801a8b9501416566974967f8a080376bc4586c8ef3da5d8e0aa17cf0d3ba")) |>
                            rawToChar()
                  )


# usethis::use_pkgdown()
pkgdown::build_site()
