import { Router } from "http://deno.land/x/oak/mod.ts";
// import { makeJwt, setExpiration, Jose, Payload } from "https://deno.land/x/djwt/create.ts";

import {
  getUsers,
  getUser,
  addUser,
  updateUser,
  deleteUser,
} from "../controllers/users.ts";
import {
  signIn,
  signUp,
  forgotPassword
} from "../controllers/usersAdv.ts";



const userRouter = new Router();

userRouter
  .get("/api/users",getUsers)
  .post("/api/signIn",signIn)
  .post("/api/signUp",signUp)
  .get("/api/users/:id",getUser)
  .put("/api/users/:id",updateUser)
  .delete("/api/users/:id",deleteUser)

  export default userRouter;
