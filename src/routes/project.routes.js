import Router from 'express';
import {
    createProject,
   
    getProjectForSDK
} from '../controllers/project.controller.js';
import { authMiddleware } from '../middleware/auth.middleware.js';


     
const projectRouter =new Router();

projectRouter.route("/create").post(authMiddleware,createProject)
projectRouter.route("sdkdetails").post(getProjectForSDK)




export default projectRouter;