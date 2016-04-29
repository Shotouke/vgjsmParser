#' obtainCVEs
#'
#' From the object that contains the CVEs xml file
#' you get a list with all the CVEs in the file
#'
#' @param doc - object with loaded file
#' @return CVEs list file
#' @examples
#' list <- obtainCVEs(doc)
obtainCVEs <- function(doc) {
  return(xpathApply(doc,"//vuln:cve-id",xmlValue))
}

#' obtainAllCPEs
#'
#' From the object that contains the CVEs xml file
#' you get a list with all the CPEs in the file
#'
#' @param doc - object with loaded file
#' @return CPEs list's file
#' @examples
#' list <- obtainAllCPEs(doc)
obtainAllCPEs <- function(doc) {
  return (xpathApply(doc,"//vuln:product"))
}

#' obtainCPEbyCVE
#'
#' From the object that contains the CVEs xml file and a CVE code
#' you get a list with all the CPEs associated
#'
#' @param doc - object with loaded file
#' @param cve - CVE to obtain CPEs
#' @return CPEs list
#' @examples
#' list <- obtainCPEbyCVE(doc,"CVE-2016-002")
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

#' obtainCVSSbyCVE
#'
#' From the object that contains the CVEs xml file and a CVE code
#' you get a list with all the CVSSs associated
#'
#' @param doc - object with loaded file
#' @param cve - CVE to obtain CVSSs
#' @return CVSSs list
#' @examples
#' list <- obtainCVSSbyCVE(doc,"CVE-2016-002")
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
