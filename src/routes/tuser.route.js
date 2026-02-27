import Router from 'express'
import{
     tenantRegister,
    tenantLogin,
    tenantLogout,
    getTenantSessions,
    revokeTenantSession
} from "../controllers/tenant.controller.js"

const tenantUserroute =new Router()

tenantUserroute.route("/tenantRegister").post(tenantRegister)
tenantUserroute.route("/tenatlogin").post(tenantLogin)
tenantUserroute.route("/tenatlogout").post(tenantLogout)


export  default tenantUserroute