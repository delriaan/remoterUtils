library(rlang, include.only = "%<~%");
source("R/!MAIN.R")
mget(ls()) |> purrr::walk(debug);

# gen_pass() ----
gen_pass(length = 30);
gen_pass(length = 30, glyphs = "#=)_$");
gen_pass(length = 30, glyphs = "#=)_$", raw = TRUE);

#
# make_cipher() ----
make_cipher(
  file_prefix = "imperialtower"
  , host_ip = "IMPERIALTOWER"
  , host_port = 65000
  , shared_key = shared_key
  , password = gen_pass(glyphs = "$_!.", length = 20)
  , export = TRUE
  );

load(dir("~", pattern = "^GW2.+data$", full.names = TRUE))
#
# make_cipher_env() ----
Sys.setenv(remoter_imperialtower = make_cipher_env());
Sys.getenv("remoter_imperialtower");
make_cipher_env(cipher = globalenv(), session = "GW2")
#
# make_batch_file() ----
make_batch_file(
  server_dir = "D:/remoter_imperialtower"
  , auth_root = path.expand("~")
  , batch.file_name = "start.bat"
  , source.file_name = "start.R"
  , sessOpts = "imperialtower"
  )
make_batch_file(
  server_dir = "D:/remoter_GW2"
  , auth_root = path.expand("~")
  , batch.file_name = "start.bat"
  , source.file_name = "start.R"
  , sessOpts = "GW2"
  )
