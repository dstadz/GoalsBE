const user = {
  id: '',
  username:'',
  password:'',
  email:'',
  /**/ signup_date:'',
}

const goals = {
  id: '',
  user_id:'',
  goal:'',
  ongoing: '',
  start_date:'',
  goal_date:''
}

const habit = {
  id:'',
  goal_id:'',
  habit_text:''
}

const vice ={ //disuader
  id:'',
  vice_id:'',
  vice_name:'',
}




const habitHistory = [{
  id:1,
  habit_id:1,
  date:'', //added when user completes as done, or end of day passes without check as false
  done: null
}]

