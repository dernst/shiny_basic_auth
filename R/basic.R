
#' @import magrittr
httphandler_auth = function(oldhandler, cred) {
    force(oldhandler)
    credstr = paste(names(cred), cred, sep=":")
    function(req) {
        ret = oldhandler(req)

        auth_ok = FALSE

        if(exists("HTTP_AUTHORIZATION", envir=req)) {
            astr = get("HTTP_AUTHORIZATION", envir=req)
            astr = sub("^Basic ", "", astr)
            astr = rawToChar(base64enc::base64decode(astr))

            if(astr %in% credstr)
                auth_ok = TRUE
        }

        if(!auth_ok) {
            return(shiny:::httpResponse(401L,
                            content=enc2utf8("invalid password"),
                            headers=list("WWW-Authenticate"="Basic realm=\"foo\" charset=\"UTF-8\"")))
        }

        oldhandler(req)
    }
}

#' Add HTTP Basic authentication to a shinyApp object
#'
#' Example usage: with_http_auth(shinyApp(ui=ui, server=server), list(user="pw"))
#' @export with_http_auth
#' @param app shinyApp object
#' @param cred named list of username/password pairs
with_http_auth = function(app, cred) {
    app$httpHandler = httphandler_auth(app$httpHandler, cred)
    app
}


