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

habitsRouter.get("/habits",getHabits)
            //.get("/habitList/:id",getHabitList)  //get single habit
            .get("/habits/:id",getHabitList)
            .post("/habits",addHabit)
            .put("/habits/:id",updateHabit)
            .delete("/habits/:id",deleteHabit)

export default habitsRouter;
 