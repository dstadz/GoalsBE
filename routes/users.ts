import { Router } from "http://deno.land/x/oak/mod.ts";
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

const usersRouter = new Router();

usersRouter.get("/api/users",getUsers)
    .get("/users",signIn)
    .get("/api/users/:id",getUser)
    .post("/api/users",signUp)
    .put("/api/users/:id",updateUser)
    .delete("/api/users/:id",deleteUser)

export default usersRouter;
