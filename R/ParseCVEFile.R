#Obtain all CVEs codes
obtainCVEs <- function(doc) {
  return(xpathApply(doc,"//vuln:cve-id",xmlValue))
}

#Obtain all CPEs separated, this is to allow us create DataFrames
obtainAllCPEs <- function(doc) {
  return (xpathApply(doc,"//vuln:product"))
}

#Obtain CPE from CVE
obtainCPEbyCVE <- function(doc, cve) {
  longLista <- length(doc) - 1
  i <- 1
  found <- FALSE

  while (i <= longLista && !found) {
    if (cve == doc[[i]]$`cve-id`) {
      found <- TRUE
      cpes <- doc[[i]]$`vulnerable-software-list`
    }
    i<-i+1
  }

  return(cpes)
}

#Obtain CPE fom CVE
obtainCVSSbyCVE <- function(doc, cve) {
  longLista <- length(doc) - 1
  i <- 1
  found <- FALSE

  while (i <= longLista && !found) {
    if (cve == doc[[i]]$`cve-id`) {
      found <- TRUE
      cvss <- doc[[i]]$cvss$base_metrics$score
    }
    i<-i+1
  }

  return(cvss)
}
