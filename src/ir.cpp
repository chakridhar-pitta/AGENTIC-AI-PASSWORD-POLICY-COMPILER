#include "ir.h"

PolicyIR::PolicyIR() {
    syncFields();
}

void PolicyIR::syncFields() {
    minLength = length.minLength;
    maxLength = length.maxLength;

    uppercaseRequired = charClass.minUpper;
    lowercaseRequired = charClass.minLower;
    minDigits = charClass.minDigit;
    minSpecial = charClass.minSpecial;

    forbidSpaces = pattern.forbidSpaces;
    sequenceLimit = pattern.sequenceLimit;
    repetitionLimit = pattern.repetitionLimit;

    blacklist = security.blacklist;
    strengthRequirement = security.strengthRequirement;

    // Sync legacy/helper accessors
    minUpper = uppercaseRequired;
    minLower = lowercaseRequired;
    minDigit = minDigits;
    requireUpper = charClass.requireUpper;
    requireLower = charClass.requireLower;
    requireDigit = charClass.requireDigit;
    requireSpecial = charClass.requireSpecial;
    noSpaces = forbidSpaces;
    maxSequence = sequenceLimit;
    maxRepeated = repetitionLimit;
    minStrength = strengthRequirement;
}

PolicyIR buildIR(const PolicyConstraints& c)
{
    PolicyIR ir;

    // 1. Populate Length IR
    ir.length.minLength = c.minLength;
    ir.length.maxLength = c.maxLength;

    // 2. Populate Character Class IR
    ir.charClass.minUpper = c.minUpper;
    ir.charClass.minLower = c.minLower;
    ir.charClass.minDigit = c.minDigit;
    ir.charClass.minSpecial = c.minSpecial;
    ir.charClass.requireUpper = (c.minUpper > 0 || c.requireUpper == 1);
    ir.charClass.requireLower = (c.minLower > 0 || c.requireLower == 1);
    ir.charClass.requireDigit = (c.minDigit > 0 || c.requireDigit == 1);
    ir.charClass.requireSpecial = (c.minSpecial > 0 || c.requireSpecial == 1);

    // 3. Populate Pattern IR
    ir.pattern.forbidSpaces = (c.noSpaces == 1);
    ir.pattern.sequenceLimit = c.maxSequence;
    ir.pattern.repetitionLimit = c.maxRepeated;

    // 4. Populate Security IR
    ir.security.blacklist = c.blacklist;
    ir.security.strengthRequirement = c.minStrength;

    // Synchronize direct properties
    ir.syncFields();

    return ir;
}
