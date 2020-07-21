import { Router } from "http://deno.land/x/oak/mod.ts";
import {
  getGoals,
  getGoal,
  addGoal,
  updateGoal,
  deleteGoal,
} from "../controllers/goals.ts";

import { getGoalList } from '../controllers/goalsAdv.ts'

const goalsRouter = new Router();

goalsRouter
  .get("/api/goals",getGoals)
  .get("/api/goals/:id",getGoalList)
  // .get("/api/goals/:id",getGoal)
  .post("/api/goals",addGoal)
  .put("/api/goals/:id",updateGoal)
  .delete("/api/goals/:id",deleteGoal)

export default goalsRouter;
