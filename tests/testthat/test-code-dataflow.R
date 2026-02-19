test_that("guard_code_dataflow creates secureguard object", {
  g <- guard_code_dataflow()
  expect_s3_class(g, "secureguard")
  expect_equal(g$type, "code")
  expect_equal(g$name, "code_dataflow")
})

test_that("safe code passes", {
  g <- guard_code_dataflow()
  result <- run_guardrail(g, "x <- 1 + 2\ny <- mean(c(1, 2, 3))")
  expect_true(result$pass)
})

# --- env_access ---

test_that("Sys.getenv is blocked", {
  g <- guard_code_dataflow(block_env_access = TRUE)
  result <- run_guardrail(g, "Sys.getenv('HOME')")
  expect_false(result$pass)
  expect_true(grepl("Sys.getenv", result$reason))
  expect_true("env_access" %in% result$details$categories)
})

test_that("Sys.setenv is blocked", {
  g <- guard_code_dataflow(block_env_access = TRUE)
  result <- run_guardrail(g, "Sys.setenv(FOO = 'bar')")
  expect_false(result$pass)
})

test_that("Sys.unsetenv is blocked", {
  g <- guard_code_dataflow(block_env_access = TRUE)
  result <- run_guardrail(g, "Sys.unsetenv('FOO')")
  expect_false(result$pass)
})

test_that(".GlobalEnv symbol is blocked", {
  g <- guard_code_dataflow(block_env_access = TRUE)
  result <- run_guardrail(g, "ls(.GlobalEnv)")
  expect_false(result$pass)
  expect_true("env_access" %in% result$details$categories)
})

test_that("globalenv() is blocked", {
  g <- guard_code_dataflow(block_env_access = TRUE)
  result <- run_guardrail(g, "globalenv()")
  expect_false(result$pass)
})

test_that("env_access can be allowed", {
  g <- guard_code_dataflow(block_env_access = FALSE)
  result <- run_guardrail(g, "Sys.getenv('HOME')")
  expect_true(result$pass)
})

# --- network ---

test_that("download.file is blocked", {
  g <- guard_code_dataflow(block_network = TRUE)
  result <- run_guardrail(g, "download.file('http://example.com', 'out.txt')")
  expect_false(result$pass)
  expect_true("network" %in% result$details$categories)
})

test_that("url() is blocked", {
  g <- guard_code_dataflow(block_network = TRUE)
  result <- run_guardrail(g, "con <- url('http://example.com')")
  expect_false(result$pass)
})

test_that("socketConnection is blocked", {
  g <- guard_code_dataflow(block_network = TRUE)
  result <- run_guardrail(g, "socketConnection(host = 'localhost', port = 8080)")
  expect_false(result$pass)
})

test_that("curl:: namespace is blocked", {
  g <- guard_code_dataflow(block_network = TRUE)
  result <- run_guardrail(g, "curl::curl_fetch_memory('http://example.com')")
  expect_false(result$pass)
  expect_true("network" %in% result$details$categories)
})

test_that("httr:: namespace is blocked", {
  g <- guard_code_dataflow(block_network = TRUE)
  result <- run_guardrail(g, "httr::GET('http://example.com')")
  expect_false(result$pass)
})

test_that("httr2:: namespace is blocked", {
  g <- guard_code_dataflow(block_network = TRUE)
  result <- run_guardrail(g, "httr2::request('http://example.com')")
  expect_false(result$pass)
})

test_that("network can be allowed", {
  g <- guard_code_dataflow(block_network = FALSE)
  result <- run_guardrail(g, "download.file('http://example.com', 'out.txt')")
  expect_true(result$pass)
})

# --- file_write ---

test_that("writeLines is blocked", {
  g <- guard_code_dataflow(block_file_write = TRUE)
  result <- run_guardrail(g, "writeLines('hello', 'out.txt')")
  expect_false(result$pass)
  expect_true("file_write" %in% result$details$categories)
})

test_that("write.csv is blocked", {
  g <- guard_code_dataflow(block_file_write = TRUE)
  result <- run_guardrail(g, "write.csv(mtcars, 'out.csv')")
  expect_false(result$pass)
})

test_that("saveRDS is blocked", {
  g <- guard_code_dataflow(block_file_write = TRUE)
  result <- run_guardrail(g, "saveRDS(x, 'out.rds')")
  expect_false(result$pass)
})

test_that("cat with file= is blocked", {
  g <- guard_code_dataflow(block_file_write = TRUE)
  result <- run_guardrail(g, "cat('hello', file = 'out.txt')")
  expect_false(result$pass)
})

test_that("cat without file= is allowed", {
  g <- guard_code_dataflow(block_file_write = TRUE)
  result <- run_guardrail(g, "cat('hello world')")
  expect_true(result$pass)
})

test_that("unlink is blocked", {
  g <- guard_code_dataflow(block_file_write = TRUE)
  result <- run_guardrail(g, "unlink('file.txt')")
  expect_false(result$pass)
})

test_that("file_write can be allowed", {
  g <- guard_code_dataflow(block_file_write = FALSE)
  result <- run_guardrail(g, "writeLines('hello', 'out.txt')")
  expect_true(result$pass)
})

# --- file_read ---

test_that("readLines is blocked when file_read blocked", {
  g <- guard_code_dataflow(block_file_read = TRUE)
  result <- run_guardrail(g, "readLines('input.txt')")
  expect_false(result$pass)
  expect_true("file_read" %in% result$details$categories)
})

test_that("read.csv is blocked when file_read blocked", {
  g <- guard_code_dataflow(block_file_read = TRUE)
  result <- run_guardrail(g, "read.csv('data.csv')")
  expect_false(result$pass)
})

test_that("source is blocked when file_read blocked", {
  g <- guard_code_dataflow(block_file_read = TRUE)
  result <- run_guardrail(g, "source('script.R')")
  expect_false(result$pass)
})

test_that("file_read allowed by default", {
  g <- guard_code_dataflow()
  result <- run_guardrail(g, "readLines('input.txt')")
  expect_true(result$pass)
})

# --- multiple categories ---

test_that("multiple categories detected together", {
  g <- guard_code_dataflow()
  code <- "Sys.getenv('KEY')\ndownload.file('http://example.com', 'out')"
  result <- run_guardrail(g, code)
  expect_false(result$pass)
  expect_true("env_access" %in% result$details$categories)
  expect_true("network" %in% result$details$categories)
})

# --- input validation ---

test_that("invalid inputs are rejected", {
  expect_error(guard_code_dataflow(block_env_access = "yes"))
  expect_error(guard_code_dataflow(block_network = 1))
  expect_error(guard_code_dataflow(block_file_write = NULL))
  expect_error(guard_code_dataflow(block_file_read = c(TRUE, FALSE)))
})
