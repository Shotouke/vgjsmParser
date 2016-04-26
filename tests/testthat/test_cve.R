context("cves-format")

cve.regex = "CVE-[[:digit:]]{4}-[[:digit:]]{4}"

test_that("cves-valid_pattern", {
  expect_true(all(grepl(pattern = cve.regex, x = rosetta$cve)))
})
