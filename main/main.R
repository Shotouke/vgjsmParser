#Load first XML file
xmlPath   <- "./inst/extdata/nvdcve-2.0-2016.xml"
xmlFile <- readXMLFile(xmlPath)
#Load second XML file
xmlPath2   <- "./inst/extdata/nvdcve-2.0-2015.xml"
xmlFile2 <- readXMLFile(xmlPath2)
df <-crear_dataframe(xmlFile, xmlFile2)
#Convert from XML to list of two files
listaNodo <- xmlToList(xmlFile)
listaNodo2<- xmlToList(xmlFile2)
#Obtain vulneravilities (CVEs) of  microsoft and android from first XML file
df <- crear_contenido(xmlFile, listaNodo,df)
df <- crear_contenido(xmlFile, listaNodo,df,"android")
#Obtain vulneravilities (CVEs) of  microsoft and android from second XML file
df <- crear_contenido(xmlFile2, listaNodo2,df)
df <- crear_contenido(xmlFile2, listaNodo2,df,"android")
