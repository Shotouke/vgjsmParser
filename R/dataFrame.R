#' initialize_dataframe
#'
#' Generates a empty dataframe with the size
#'  of all the CPEs of the file
#'
#' @param file1, file2, .... Objects with xml of the files to process
#' @return empty dataframe with the maximum number of CPEs
#' @examples
#' df <- initialize_dataframe(xmlFile, xmlFile2)
initialize_dataframe <- function(...) {
  max <- 0
  for (x in list(...)) {
    max <- max + length(obtainAllCPEs(doc = x))
  }

  df<-data.frame(cve = character(max), cpe = character(max), cvss = numeric(max), year = character(max), so = character(max))

  df$cve <- as.character(df$cve)
  df$cpe <- as.character(df$cpe)
  df$year <- as.character(df$year)
  df$so <- as.character(df$so)

  return(df)
}

#' save_content
#'
#' Insert the CVEs, CPEs and CVSSs for
#' the inserted OS
#'
#' @param xmlFile - xml de los CVE's
#' @param listNodes - xml separated like a list
#' @param df - dataframe
#' @param cpe - OS to search
#' @return Dataframe with OS information
#' @examples
#' df <- save_content(xmlFile, listaNodo,df,"android")
save_content <- function(xmlFile, nodesList, df, cpe) {

  cves <- obtainCVEs(doc = xmlFile)
  cvesLength <- length(cves)

  dfCounter <- obtainLastElement(df = df)
  for (i in 1:cvesLength) {
    cpes <- obtainCPEbyCVE(doc = nodesList, cve = cves[[i]])
    cvss <- obtainCVSSbyCVE(doc = nodesList, cve = cves[[i]])

    c <- grep("cpe:/o:", grep(cpe, cpes, ignore.case = TRUE ,value = TRUE), ignore.case = TRUE ,value = TRUE)
    cpesLength <- length(c)

    if (cpesLength > 0) {
      for (j in 1:cpesLength) {
        df[dfCounter,1] <- cves[[i]]
        df[dfCounter,2] <- c[[j]]
        df[dfCounter,3] <- cvss[[1]]
        df[dfCounter,4] <- substr(cves[[1]], 5, 8)
        df[dfCounter, 5] <- cpe
        dfCounter <- dfCounter + 1
      }
    }
  }

  return(df)
}

#' obtainLastElement
#'
#' Obtains the first empty position in the dataframe
#'
#' @param df - dataframe
#' @return first empty position
#' @examples
#' pos <- obtainLastElement(df)
obtainLastElement <- function(df) {
  cveLength <- length(df$cve)
  found <- FALSE
  pos <- 1
  while (pos <= cveLength && !found) {
    if (df$cve[[pos]] == "")
      found <- TRUE
    else
      pos <- pos + 1
  }

  return(pos)
}

#' deleteEmptyRow
#'
#' Compacts the dataframe and returns only complete rows
#'
#' @param df - dataframe with data
#' @return compacted dataframe
#' @examples
#' df <- deleteEmptyRows(df)
deleteEmptyRows <- function(df) {
  return(head(df, n = obtainLastElement(df)))
}
