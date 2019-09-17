// @ts-ignore
import { think } from 'thinkjs'
// @ts-ignore
import svgCaptcha from 'svg-captcha'

export interface IConf {
  cachePrefix: string,
  codePool: string,
  ipMaxNum: number,
  imgTimeout: number,
  imgMaxNum: number,
  imgLen: number,
  codeTimeout: number,
  codeMaxNum: number,
  interval: number,
  errMaxNum: number,
  numLen: number
}

export default class Captcha extends think.Service {
  conf: IConf

  constructor(conf?: IConf) {
    super()
    const dfOpts = {
      cachePrefix: 'captcha-full',
      codePool: 'abcdefgkmpqrstuvwsyzABCDEFGHJKLMNPRSTUVWXYZ123456789',
      ipMaxNum: 10,
      imgTimeout: 5 * 60,
      imgMaxNum: 3,
      imgLen: 4,
      codeTimeout: 10 * 60,
      codeMaxNum: 5,
      interval: 60,
      errMaxNum: 5,
      numLen: 6
    }
    const dfConf = think.config('captcha')
    this.conf = Object.assign(dfOpts, dfConf, conf)
  }

  getCode(type = 'num'): string | number {
    let code: number | string = ''
    if (type === 'num') {
      const maxNum = Math.pow(10, this.conf.numLen)
      const minNum = maxNum / 10
      code = Math.random() * maxNum
      code = code < maxNum / 10 ? code + minNum : code
      return Math.floor(code)
    }
    const pool = this.conf.codePool
    const len = pool.length
    for (let i = 0; i < this.conf.imgLen; i += 1) {
      const index = Math.floor(Math.random() * len)
      code += pool[index]
    }
    return code
  }

  // 错误次数是否超过限制 场景：登录密码错误次数，显示图形验证码
  async isErrOut({ action, sign }: { action: string, sign: string }) {
    const cacheKey = `${this.conf.cachePrefix}-${sign}-isErrOut-${action}`
    let alsoNum = await think.cache(cacheKey) || this.conf.errMaxNum
    alsoNum -= 1
    if (alsoNum < 1) {
      return true
    }
    think.cache(cacheKey, alsoNum)
    return false
  }

  // 重置错误次数 场景：登录是 图形验证码通过
  async reErrOut({ action, sign }: { action: string, sign: string }) {
    const cacheKey = `${this.conf.cachePrefix}-${sign}-isErrOut-${action}`
    think.cache(cacheKey, null)
    return true
  }

  // ip是否需要验证码 场景：注册获取手机验证码，次数过多，显示图形验证码
  async ipIsNeed({ action, ip }: { action: string, ip: string }) {
    const cacheKey = `${this.conf.cachePrefix}-${ip}-notNeedNum-${action}`
    let notNeedNum = await think.cache(cacheKey) || this.conf.ipMaxNum
    notNeedNum -= 1
    if (notNeedNum < 1) {
      return true
    }
    think.cache(cacheKey, notNeedNum)
    return false
  }

  // 重置ip需要验证码次数 场景：登录时 图形验证码通过
  async reIpNeed({ action, ip }: { action: string, ip: string }) {
    const cacheKey = `${this.conf.cachePrefix}-${ip}-notNeedNum-${action}`
    think.cache(cacheKey, null)
    return true
  }

  async sendImg(action: string) {
    const captcha = svgCaptcha.create({ size: 4 })
    const code = captcha.text
    const img = captcha.data
    const uuid = think.uuid('v1')
    think.cache(`${this.conf.cachePrefix}-${action}-${uuid}`, {
      // @ts-ignore
      code,
      num: this.conf.imgMaxNum,
      time: new Date().getTime()
    })
    return { code, uuid, img }
  }

  async verifyImg({ action, code, uuid }: { action: string, code: string, uuid: string }) {
    if (!action || !code || !uuid) {
      return { code: 410001, msg: '请输入图形验证码', data: this.sendImg.call(this, action) }
    }
    const cacheKey = `${this.conf.cachePrefix}-${action}-${uuid}`
    const codeObj = await think.cache(cacheKey)
    if (think.isEmpty(codeObj)) {
      return { code: 410001, msg: '请输入图形验证码', data: this.sendImg.call(this, action) }
    }
    const curTime = new Date().getTime()
    // 超时 重新生成
    const timeLeft = (codeObj.time - curTime) + (this.conf.imgTimeout * 1000)
    if (timeLeft < 0) {
      think.cache(cacheKey, null)
      return { code: 410001, msg: '超过时间限制，请重新获取', data: this.sendImg.call(this, action) }
    }
    if (!(codeObj.code && codeObj.code.toLocaleUpperCase() === code.toLocaleUpperCase())) {
      codeObj.num -= 1
      // 次数超过限制
      if (codeObj.num < 1) {
        think.cache(cacheKey, null)
        return { code: 410001, msg: '出错次数太多，请重新获取', data: this.sendImg.call(this, action) }
      }
      think.cache(cacheKey, codeObj)
      return { code: 401001, msg: '验证失败，请确认输入' }
    }
    think.cache(cacheKey, null)
    return { code: 0, msg: '验证成功' }
  }

  async sendCode({ action, sign }: { action: string, sign: string }) {
    const cacheKey = `${this.conf.cachePrefix}-${action}-${sign}`
    const codeObj = await think.cache(cacheKey)
    if (!think.isEmpty(codeObj)) {
      const curTime = new Date().getTime()
      const timeLeft = (codeObj.time - curTime) + (this.conf.interval * 1000)
      if (timeLeft > 0) {
        return {
          code: 403004,
          msg: `${this.conf.interval} 秒内只能获取一次`,
          data: { timeLeft: timeLeft / 1000 }
        }
      }
    }
    const code = this.getCode()
    think.cache(`${this.conf.cachePrefix}-${action}-${sign}`, {
      // @ts-ignore
      code,
      num: this.conf.codeMaxNum,
      time: new Date().getTime()
    })
    return { code: 0, data: { code, timeout: this.conf.codeTimeout } }
  }

  async verifyCode({ action, code, sign }: { action: string, code: number | string, sign: string }) {
    const cacheKey = `${this.conf.cachePrefix}-${action}-${sign}`
    const codeObj = await think.cache(cacheKey)
    if (think.isEmpty(codeObj)) {
      return { code: 410001, msg: '验证码错误，请重新获取' }
    }
    const curTime = new Date().getTime()
    const timeLeft = (codeObj.time - curTime) + (this.conf.codeTimeout * 1000)
    if (timeLeft < 0) {
      think.cache(cacheKey, null)
      return { code: 410001, msg: '超过时间限制，请重新获取' }
    }
    codeObj.num -= 1
    // 次数超过限制
    if (codeObj.num < 1) {
      think.cache(cacheKey, null)
      return { code: 410001, msg: '出错次数太多，请重新获取' }
    }
    if (codeObj.code + '' !== code + '') {
      return { code: 401001, msg: '验证失败，请确认输入' }
    }
    think.cache(cacheKey, null)
    return { code: 0, msg: '验证成功' }
  }
}
