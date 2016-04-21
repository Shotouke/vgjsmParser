crear_dataframe <- function(cves, cpes, cvss ) {
  max.cve <- length(cves)
  max.cpe <- length(cpes)
  max.cvss <- length(cvss)

  max <- max(max.cve, max.cpe, max.cvss)

  df <- data.frame(cve = character(max),
             cpe = character(max),
             cvss = numeric(max))
  return(df)
}
