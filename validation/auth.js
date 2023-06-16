import joi from "joi";

export const ValidateSignup = (userData) => {

  const Schema = joi.object({
    userName: joi.string(),
    email: joi.string().email(),
    password: joi.string(),
    address: joi.string(),
    city: joi.string(),
    status: joi.string(),
  });
  // console.log(userData);
return Schema.validateAsync(userData);

};
export const ValidateSignin = (userData) => {

const Schema = joi.object({
  userName: joi.string(),
  password: joi.string().min(5).required(),
  email : joi.string().required()
});

return Schema.validateAsync(userData);

};

export const ValidateEmail = (data)=>{

  const Schema = joi.object({
    email: joi.string().email().required()
  })

  return Schema.validateAsync(data);
}