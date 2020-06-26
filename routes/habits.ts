import { Router } from "http://deno.land/x/oak/mod.ts";
import {
  getHabits,
  getHabit,
  addHabit,
  updateHabit,
  deleteHabit,
} from "../controllers/habits.ts";

const habitRouter = new Router();

habitRouter.get("/api/habits",getHabits)
    .get("/api/habits/:id",getHabit)
    .post("/api/habits",addHabit)
    .put("/api/habits/:id",updateHabit)
    .delete("/api/habits/:id",deleteHabit)

export default habitRouter;
