xmlPath   <- "./inst/extdata/nvdcve-2.0-2016.xml"
xmlFile <- readXMLFile(xmlPath)
#child <- obtencve (xmlFile,"CVE-2016-002")
#xpath <- "//entry[@id='CVE-2016-0002']/vuln:vulnerable-software-list/vuln:product"
#doc <- gsub(pattern = "vuln:v", replacement = "vuln_v", x = xmlFile)
#c<- xpathApply(xmlFile,"//entry[@id='CVE-2016-0002']/vuln:vulnerable-software-list")
#print(c)
# cpe <- unlist(obtenerCPEs(xmlFile))
df <-crear_dataframe(xmlFile)

