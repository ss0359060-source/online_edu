package com.online.edu.ucenter.controller;

import cn.hutool.core.util.IdUtil;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.online.edu.common.R;
import com.online.edu.ucenter.entity.Member;
import com.online.edu.ucenter.entity.dto.LoginDto;
import com.online.edu.ucenter.service.MemberService;
import com.online.edu.ucenter.utils.JwtUtils;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/ucenter/user")
@CrossOrigin
public class UserController {

    @Autowired
    private MemberService memberService;

    @PostMapping("registerUser")
    public R registerUser(@RequestBody Member member) {
        try {
            String salt = IdUtil.simpleUUID().toUpperCase();
            member.setSalt(salt);
            member.setPassword(new Md5Hash(member.getPassword(), salt, 2).toString());
            member.setIsDeleted(false);
            member.setIsDisabled(false);
            this.memberService.save(member);
            return R.ok();
        } catch (Exception e) {
            e.printStackTrace();
            return R.error();
        }
    }

    @PostMapping("login")
    public R loginUser(@RequestBody LoginDto loginDto) {
        QueryWrapper<Member> wrapper = new QueryWrapper<>();
        wrapper.eq("mobile", loginDto.getMobile());
        wrapper.eq("is_deleted", false);
        Member member = memberService.getOne(wrapper);
        if (member == null || Boolean.TRUE.equals(member.getIsDisabled())) {
            return R.error().message("用户不存在或已禁用");
        }

        String inputPassword;
        if (member.getSalt() != null && !"".equals(member.getSalt())) {
            inputPassword = new Md5Hash(loginDto.getPassword(), member.getSalt(), 2).toString();
        } else {
            inputPassword = new Md5Hash(loginDto.getPassword()).toString();
        }

        if (!inputPassword.equals(member.getPassword())) {
            return R.error().message("手机号或密码错误");
        }

        String userToken = JwtUtils.genJsonWebToken(member);
        return R.ok().data("token", userToken);
    }
}
