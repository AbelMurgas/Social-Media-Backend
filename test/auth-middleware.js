import authMiddleware from "../middleware/is-auth.js";
import chai from "chai";

const expect = chai.expect;

it("should throw an error if no authorization header is present", function () {
  const req = {
    get: function (headerName) {
		return null
	},
  };
  expect(authMiddleware.bind(this,req, {}, () => {})).to.throw("Not authenticated.");
});
