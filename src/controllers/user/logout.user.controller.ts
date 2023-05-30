import { Response } from "express";
import { VerifyRequest } from "../../middleware/verifyJwt";
import UserModel from "../../model/user.model";
import { TokenPayload } from "../../utils/jwt.utils";

// // Logout User
// export const handleLogoutForEmail = async (
//   req: VerifyRequest<null, TokenPayload, null>,
//   res: Response
// ) => {
//   const { userUniqueIdentity } = req.body;

//   // username doesn't exist in jwt token
//   if (!userUniqueIdentity)
//     return res
//       .status(200)
//       .json({ message: "logged out", type: "success", isAuthenticated: false });

//   const user = await UserModel.findOneAndUpdate(
//     { email: userUniqueIdentity },
//     { refreshToken: "null" }
//   );

//   // username doesn't exist in db
//   if (!user)
//     return res
//       .status(200)
//       .json({ message: "logged out", type: "success", isAuthenticated: false });

//   // clear cookie
//   res.clearCookie("jwt", {
//     httpOnly: true,
//     secure: false,
//     sameSite: "none",
//     maxAge: 30 * 24 * 60 * 60 * 1000,
//   });

//   res.status(200).json({
//     message: `user ${user.username} was successfully logged out`,
//     type: "success",
//     isAuthenticated: false,
//   });
// };

export const handleLogout = async (
  req: VerifyRequest<null, TokenPayload, null>,
  res: Response
) => {
  const { userUniqueIdentity, provider } = req.body;

  // username doesn't exist in jwt token
  if (!userUniqueIdentity)
    return res
      .status(200)
      .json({ message: "logged out", type: "success", isAuthenticated: false });

  if (provider === "Email") {
    const user = await UserModel.findOneAndUpdate(
      { email: userUniqueIdentity },
      { refreshToken: "null" }
    );

    // username doesn't exist in db
    if (!user)
      return res.status(200).json({
        message: "logged out",
        type: "success",
        isAuthenticated: false,
      });

    // clear cookie
    res.clearCookie("jwt", {
      httpOnly: true,
      secure: false,
      sameSite: "none",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      message: `user ${user.username} was successfully logged out`,
      type: "success",
      isAuthenticated: false,
    });
  } else if (provider === "google") {
    const user = await UserModel.findOneAndUpdate(
      { email: userUniqueIdentity },
      { refreshToken: "null", accessToken: null }
    );

    // username doesn't exist in db
    if (!user) {
      return res.status(200).json({
        message: "logged out",
        type: "success",
        isAuthenticated: false,
      });
    } else {
      req.session.destroy((err) => {
        if (err) {
          res.status(500).json({
            err,
          });
        } else {
          res.clearCookie("connect.sid");
          res.clearCookie("jwt");
          res.status(200).json({
            message: "logged out Google oauth 2.0 successfully",
            type: "success",
            isAuthenticated: false,
          });
        }
      });
    }
  } else {
    const user = await UserModel.findOneAndUpdate(
      { Mobile_No: userUniqueIdentity },
      { refreshToken: "null" }
    );
    // username doesn't exist in db
    if (!user)
      return res.status(200).json({
        message: "logged out",
        type: "success",
        isAuthenticated: false,
      });

    // clear cookie
    res.clearCookie("jwt", {
      httpOnly: true,
      secure: false,
      sameSite: "none",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.clearCookie("connect.sid", {
      httpOnly: true,
      secure: false,
      sameSite: "none",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      message: `user ${user.username} was successfully logged out`,
      type: "success",
      isAuthenticated: false,
    });
  }
};
