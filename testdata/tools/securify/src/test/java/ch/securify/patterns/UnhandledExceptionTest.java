/*
 *  Copyright 2018 Secure, Reliable, and Intelligent Systems Lab, ETH Zurich
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package ch.securify.patterns;

import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertEquals;

public class UnhandledExceptionTest {

    @Test
    public void isViolation() throws IOException {
        String hex = "src/test/resources/solidity/UnhandledException.bin.hex";
        HelperInstructionPattern helperInstructionPattern = new HelperInstructionPattern(hex, new UnhandledException());
        assertEquals(1, helperInstructionPattern.pattern.violations.size());
    }

    @Test
    public void isViolation2() throws IOException {
        String hex = "src/test/resources/solidity/UnhandledException2.bin.hex";
        HelperInstructionPattern helperInstructionPattern = new HelperInstructionPattern(hex, new UnhandledException());
        assertEquals(1, helperInstructionPattern.pattern.violations.size());
    }
}