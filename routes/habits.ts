import { Router } from "http://deno.land/x/oak/mod.ts";
import {
  getHabits,
  getHabit,
  getHabitList,
  addHabit,
  updateHabit,
  deleteHabit,
} from "../controllers/habits.ts";

const habitsRouter = new Router();

habitsRouter.get("/api/habits",getHabits)
            //.get("/api/habitList/:id",getHabitList)  //get single habit
            .get("/api/habits/:id",getHabitList)
            .post("/api/habits",addHabit)
            .put("/api/habits/:id",updateHabit)
            .delete("/api/habits/:id",deleteHabit)

export default habitsRouter;
