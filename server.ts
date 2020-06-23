import { Application, Router } from 'http://deno.land/x/oak/mod.ts'
import router from './routes.ts'
const port = 8000

const app = new Application()

app.use(router.routes())
app.use(router.allowedMethods())

console.log(`server live on port  ${port}`)
console.log('Hello Terra')

await app.listen({ port })