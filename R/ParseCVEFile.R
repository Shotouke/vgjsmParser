obtenerCVEs <- function(doc) {
  return(xpathApply(doc,"//vuln:cve-id",xmlValue))
}

obtenerCPEs <- function(doc) {
  return(xpathApply(doc,"//vuln:vulnerable-software-list",xmlValue))
}

obtenerCVSS <- function(doc) {
  return(xpathApply(doc,"//cvss:score",xmlValue))
}

obtenerAccesVector <- function(doc) {
  return(xpathApply(doc,"//cvss:access-vector",xmlValue))
}

montarDF <- function(doc) {
  return (
    data.frame (
      "cves"=c(unlist(obtenerCVEs(doc))),
      "cpes"=c(unlist(obtenerCPEs(doc))),
      "cvss"=c(unlist(obtenerCVSS(doc))))
  )
}
