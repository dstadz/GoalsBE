import { Router } from "http://deno.land/x/oak/mod.ts";
import {
  getUsers,
  getUser,
  addUser,
  updateUser,
  deleteUser,
} from "./controllers/users.ts";

const router = new Router();

router.get("/api/users",getUsers)
    .get("/api/users/:id",getUser)
    .post("/api/users",addUser)
    .put("/api/users/:id",updateUser)
    .delete("/api/users/:id",deleteUser)

export default router;
