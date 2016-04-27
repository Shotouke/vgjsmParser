
initialize_dataframe <- function(...) {
  max <- 0
  for (x in list(...)) {
    max <- max + length(obtainAllCPEs(doc = x))
  }

  df<-data.frame(cve = character(max), cpe = character(max), cvss = numeric(max), year = character(max))

  df$cve <- as.character(df$cve)
  df$cpe <- as.character(df$cpe)
  df$year <- as.character(df$year)

  return(df)
}

save_content <- function(xmlFile, nodesList, df, cpe) {

  cves <- obtainCVEs(doc = xmlFile)
  cvesLength <- length(cves)

  dfCounter <- obtainLastElement(df = df)
  for (i in 1:cvesLength) {
    cpes <- obtainCPEbyCVE(doc = nodesList, cve = cves[[i]])
    cvss <- obtainCVSSbyCVE(doc = nodesList, cve = cves[[i]])

    c <- grep(paste("cpe:/o:",cpe,sep=""),cpes,ignore.case = T, value = T)
    cpesLength <- length(c)

    if (cpesLength > 0) {
      for (j in 1:cpesLength) {
        df[dfCounter,1] <- cves[[i]]
        df[dfCounter,2] <- c[[j]]
        df[dfCounter,3] <- cvss[[1]]
        df[dfCounter,4] <- substr(cves[[1]],5,8)
        dfCounter <- dfCounter + 1
      }
    }
  }

  return(df)
}

obtainLastElement <- function(df) {
  longcve <- length(df$cve)
  found <- FALSE
  pos <- 1
  while (pos <= longcve && !found) {
    if (df$cve[[pos]]=="")
      found <- TRUE
    else
      pos <- pos + 1
  }
  return(pos)
}
