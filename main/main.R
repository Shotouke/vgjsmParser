xmlPath   <- "./inst/extdata/nvdcve-2.0-2016.xml"
xmlFile <- readXMLFile(xmlPath)
xmlPath2   <- "./inst/extdata/nvdcve-2.0-2015.xml"
xmlFile2 <- readXMLFile(xmlPath2)
df <-crear_dataframe(xmlFile, xmlFile2)
listaNodo <- xmlToList(xmlFile)
listaNodo2<- xmlToList(xmlFile2)
df <- crear_contenido(xmlFile, listaNodo,df)
df <- crear_contenido(xmlFile, listaNodo,df,"androld")
