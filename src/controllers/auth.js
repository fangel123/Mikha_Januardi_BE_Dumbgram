// import model
const { user } = require("../../models");

// import joi validation
const joi = require("joi");
// import bcrypt
const bcrypt = require("bcrypt");
//import jsonwebtoken
const jwt = require("jsonwebtoken");

exports.register = async (req, res) => {


  let data = req.body

  if(!data.status){
      data = {
          ...data,
          status: 'customer',
      };
  };

  const schema = joi.object({
      name:joi.string().min(4).required(),
      email:joi.string().email().required(),
      password:joi.string().min(6).required(),
      status:joi.string(),
  });

  const { error }= schema.validate(data);

  if (error) {
      return res.send({
          error:{
              message: error.details[0].message,
          },
      });
  }

  const isAlready = await user.findOne({
      where: {
          email: data.email
      }
  })

  if(isAlready){
      return res.status(400).send({
          error: {
              message: `Email ${data.email} is Already`,
          }
      })
  }
  try {

  const hashedPassword = await bcrypt.hash(req.body.password, 10)

  const newUser = await user.create({
      name: data.name,
      email: data.email,
      password: hashedPassword,
      status: data.status,
  })


  const SECRET_KEY = 'tokenlistrik';
  const token = jwt.sign({id:newUser.id}, SECRET_KEY);

  res.status(200).send({
      status: 'success',
      data:{
          id: newUser.id,
          name: newUser.name,
          email: newUser.email,
          token,
      }
  });

} catch (error) {
  console.log(error)
  res.status(500).send({
      status: 'failed',
      message:'server error',
  })
}

};

// Login
exports.login = async (req, res) => {
  try {

    const data = req.body;

    const schema = joi.object({
        email: joi.string().email().required(),
        password: joi.string().required(),
    });

    const { error } = schema.validate(data);

    if(error){
        return res.status(400).send({
            error: {
                message: error.details[0].message
            }
        });
    };

    const accountExist = await user.findOne({
        where: {
            email: data.email,
        }
    });

    if(!accountExist){
        return res.status(400).send({
            error: {
                message: `Account ${data.email} not found`
            }
        });
    };

    const isValid = await bcrypt.compare(data.password, accountExist.password);

    if(!isValid) {
        return res.status(400).send({
            error: {
                message: `Email or Password is not Matching`
            }
        });
    };

    const payload = { 
        id: accountExist.id,
        name: accountExist.name,
        email: accountExist.email,
        status: accountExist.status 
    };

    const SECRET_KEY = "tokenlistrik"

    const token = jwt.sign(payload, SECRET_KEY);

    res.send({
        status: 'Success',
        data: {
            user: {
                name: accountExist.name,
                email: accountExist.email,
                status: accountExist.status,
                token
            }
        },
    });
    
} catch (error) {
    console.log(error)
    res.send({
        status: 'Failed',
        message: 'Server Error'
    });
}
};