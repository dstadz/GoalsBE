import { Router } from "http://deno.land/x/oak/mod.ts";
import { makeJwt, setExpiration, Jose, Payload } from "https://deno.land/x/djwt/create.ts";

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


// const key = "secret-key";
// const payload: Payload = {
//   iss: "Jon Doe",
//   exp: setExpiration(new Date().getTime() + 60000),
// };
// const header: Jose = {
//   alg: "HS256",
//   typ: "JWT",
// };

const userRouter = new Router();

userRouter
  .get("/api/users",getUsers)
  .post("/api/signIn",signIn)
  .get("/api/users/:id",getUser)
  .post("/signUp",signUp)
  .put("/api/users/:id",updateUser)
  .delete("/api/users/:id",deleteUser)

  // .get("/", (context) => {
  //   context.response.body = "JWT Example!";
  // })
  // .get("/generate", (context) => {
  //   context.response.body = makeJwt({ header, payload, key }) + "\n";
  // })

  export default userRouter;
