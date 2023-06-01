import { Request, Response } from "express";
import UserModel from "../../model/user.model";
import { TokenPayload } from "../../utils/jwt.utils";
import { getUserFromEmailOrNumber } from "../../utils/user/getUserFromEmailOrNumber";

export const getAllAddress = async (
  req: Request<{}, {}, TokenPayload>,
  res: Response
) => {
  const { userUniqueIdentity, provider } = req.body;
  var user = await getUserFromEmailOrNumber(userUniqueIdentity);
  if (!user) {
    return res.status(401).json({
      message: "user not found",
      type: "error",
      isAuthenticated: false,
    }); // U
  }
  const Address = user.address;
  res.status(200).json({
    type: "success",
    Address,
  });
};
